package io.opentdf.platform.sdk;

import com.connectrpc.Code;
import com.connectrpc.ConnectException;
import com.connectrpc.impl.ProtocolClient;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.opentdf.platform.kas.AccessServiceClient;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.PublicKeyResponse;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.kas.RewrapResponse;
import io.opentdf.platform.sdk.SDK.KasBadRequestException;
import io.opentdf.platform.sdk.spi.KemProvider;
import io.opentdf.platform.sdk.spi.KemProviders;

import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.function.BiFunction;

import static io.opentdf.platform.sdk.TDF.GLOBAL_KEY_SALT;

/**
 * A client implementation that communicates with a Key Access Service (KAS).
 * This class provides methods to retrieve public keys, unwrap encrypted keys,
 * and manage key caches.
 */
class KASClient implements SDK.KAS {

    private final OkHttpClient httpClient;
    private final BiFunction<OkHttpClient, String, ProtocolClient> protocolClientFactory;
    private final boolean usePlaintext;
    private final JWSSigner signer;
    private volatile AsymDecryption decryptor;
    private volatile String clientPublicKey;
    private KASKeyCache kasKeyCache;

    private static final Logger log = LoggerFactory.getLogger(KASClient.class);

    /***
     * A client that communicates with KAS
     * 
     *                       communicate
     * @param srtSigner
     */
    KASClient(OkHttpClient httpClient, BiFunction<OkHttpClient, String, ProtocolClient> protocolClientFactory, SrtSigner srtSigner, boolean usePlaintext) {
        this.httpClient = httpClient;
        this.protocolClientFactory = protocolClientFactory;
        this.usePlaintext = usePlaintext;
        if (srtSigner == null) {
            throw new SDKException("srtSigner must be provided");
        }
        this.signer = new SrtJwsSigner(srtSigner);
        this.kasKeyCache = new KASKeyCache();
    }

    @Override
    public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
        Config.KASInfo cachedValue = this.kasKeyCache.get(kasInfo.URL, kasInfo.Algorithm, kasInfo.KID);
        if (cachedValue != null) {
            return cachedValue;
        }

        PublicKeyRequest request = (kasInfo.Algorithm == null || kasInfo.Algorithm.isEmpty())
                ? PublicKeyRequest.getDefaultInstance()
                : PublicKeyRequest.newBuilder().setAlgorithm(kasInfo.Algorithm).build();

        var req = getStub(kasInfo.URL).publicKeyBlocking(request, Collections.emptyMap()).execute();
        PublicKeyResponse resp;
        try {
            resp = RequestHelper.getOrThrow(req);
        } catch (ConnectException e) {
            throw new SDKException("error getting public key", e);
        }

        var kiCopy = new Config.KASInfo();
        kiCopy.KID = resp.getKid();
        kiCopy.PublicKey = resp.getPublicKey();
        kiCopy.URL = kasInfo.URL;
        kiCopy.Algorithm = kasInfo.Algorithm;

        this.kasKeyCache.store(kiCopy);
        return kiCopy;
    }

    @Override
    public KASKeyCache getKeyCache() {
        return this.kasKeyCache;
    }

    @Override
    public synchronized void close() {
        this.httpClient.dispatcher().cancelAll();
        this.httpClient.connectionPool().evictAll();
    }

    static class RewrapRequestBody {
        String policy;
        String clientPublicKey;
        Manifest.KeyAccess keyAccess;
    }

    private static final Gson gson = new Gson();

    /** Session-key material generated for a single unwrap() call: the PEM to send to KAS, plus whichever private key is needed to process the response. */
    private static final class SessionKeyMaterial {
        final String publicKeyPem;
        final ECKeyPair ecKeyPair;
        final KemProvider.KeyPairPem kemKeyPair;

        SessionKeyMaterial(String publicKeyPem, ECKeyPair ecKeyPair, KemProvider.KeyPairPem kemKeyPair) {
            this.publicKeyPem = publicKeyPem;
            this.ecKeyPair = ecKeyPair;
            this.kemKeyPair = kemKeyPair;
        }
    }

    private SessionKeyMaterial generateSessionKeyMaterial(KeyType sessionKeyType) {
        if (sessionKeyType.isEc()) {
            var curve = sessionKeyType.getECCurve();
            ECKeyPair ecKeyPair = new ECKeyPair(curve);
            return new SessionKeyMaterial(ecKeyPair.publicKeyInPEMFormat(), ecKeyPair, null);
        }
        if (sessionKeyType.isMLKEM()) {
            KemProvider.KeyPairPem kemKeyPair = KemProviders.get(sessionKeyType).generateKeyPair(sessionKeyType);
            return new SessionKeyMaterial(kemKeyPair.publicKeyPEM, null, kemKeyPair);
        }
        // Initialize the RSA key pair only once and reuse it for future unwrap
        // operations. Double-checked locking: decryptor/clientPublicKey are
        // volatile so the initializing thread's write is visible to others,
        // and the synchronized block keeps two concurrent first-callers from
        // generating distinct keypairs and racing to overwrite each other's
        // fields (which would send one generation's public key while
        // decrypting with another's private key).
        if (decryptor == null) {
            synchronized (this) {
                if (decryptor == null) {
                    var encryptionKeypair = CryptoUtils.generateRSAKeypair();
                    decryptor = new AsymDecryption(encryptionKeypair.getPrivate());
                    clientPublicKey = CryptoUtils.getRSAPublicKeyPEM(encryptionKeypair.getPublic());
                }
            }
        }
        return new SessionKeyMaterial(clientPublicKey, null, null);
    }

    private byte[] unwrapResponseKey(
            KeyType sessionKeyType, SessionKeyMaterial keyMaterial, RewrapResponse response, byte[] wrappedKey) {
        if (sessionKeyType.isEc()) {
            if (keyMaterial.ecKeyPair == null) {
                throw new SDKException("ECKeyPair is null. Unable to proceed with the unwrap operation.");
            }

            var kasEphemeralPublicKey = response.getSessionPublicKey();
            ECPublicKey publicKey;
            try {
                publicKey = ECKeyPair.publicKeyFromPem(kasEphemeralPublicKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SDKException("error decoding KAS session public key", e);
            }
            byte[] symKey = ECKeyPair.computeECDHKey(publicKey, keyMaterial.ecKeyPair.getPrivateKey());

            var sessionKey = ECKeyPair.calculateHKDF(GLOBAL_KEY_SALT, symKey);

            AesGcm gcm = new AesGcm(sessionKey);
            AesGcm.Encrypted encrypted = new AesGcm.Encrypted(wrappedKey);
            return gcm.decrypt(encrypted);
        }
        if (sessionKeyType.isMLKEM()) {
            if (keyMaterial.kemKeyPair == null) {
                throw new SDKException("KEM keypair is null. Unable to proceed with the unwrap operation.");
            }
            return KemProviders.get(sessionKeyType).unwrapDEK(sessionKeyType, keyMaterial.kemKeyPair.privateKeyPEM, wrappedKey);
        }
        return decryptor.decrypt(wrappedKey);
    }

    @Override
    public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy,  KeyType sessionKeyType) {
        SessionKeyMaterial keyMaterial = generateSessionKeyMaterial(sessionKeyType);

        RewrapRequestBody body = new RewrapRequestBody();
        body.policy = policy;
        body.clientPublicKey = keyMaterial.publicKeyPem;
        body.keyAccess = keyAccess;

        var requestBody = gson.toJson(body);
        var claims = new JWTClaimsSet.Builder()
                .claim("requestBody", requestBody)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
                .build();

        var jws = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT jwt = new SignedJWT(jws, claims);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new SDKException("error signing KAS request", e);
        }

        var request = RewrapRequest
                .newBuilder()
                .setSignedRequestToken(jwt.serialize())
                .build();
        RewrapResponse response;
        var req = getStub(keyAccess.url).rewrapBlocking(request, Collections.emptyMap()).execute();
        try {
            response = RequestHelper.getOrThrow(req);
        } catch (ConnectException e) {
            if (e.getCode() == Code.INVALID_ARGUMENT) {
                // 400 Bad Request
                throw new KasBadRequestException("rewrap request 400: " + e);
            }
            throw new SDKException("error unwrapping key", e);
        }

        var wrappedKey = response.getEntityWrappedKey().toByteArray();
        return unwrapResponseKey(sessionKeyType, keyMaterial, response, wrappedKey);
    }

    private final HashMap<String, AccessServiceClient> stubs = new HashMap<>();

    // make this protected so we can test the address normalization logic
    synchronized AccessServiceClient getStub(String url) {
        return stubs.computeIfAbsent(AddressNormalizer.normalizeAddress(url, usePlaintext), (String address) -> {
            var client = protocolClientFactory.apply(httpClient, address);
            return new AccessServiceClient(client);
        });
    }

    private static final class SrtJwsSigner implements JWSSigner {
        private static final JWSAlgorithm EXPECTED_ALG = JWSAlgorithm.RS256;
        private final SrtSigner srtSigner;
        private final JCAContext jcaContext = new JCAContext();

        private SrtJwsSigner(SrtSigner srtSigner) {
            this.srtSigner = srtSigner;
            if (!EXPECTED_ALG.getName().equals(srtSigner.alg())) {
                throw new SDKException("unsupported SRT signing algorithm: " + srtSigner.alg());
            }
        }

        @Override
        public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
            if (!EXPECTED_ALG.equals(header.getAlgorithm())) {
                throw new JOSEException("SRT signer algorithm mismatch: " + header.getAlgorithm());
            }

            try {
                return Base64URL.encode(srtSigner.sign(signingInput));
            } catch (java.security.GeneralSecurityException e) {
                throw new JOSEException("error signing SRT payload", e);
            }
        }

        @Override
        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
            return Collections.singleton(EXPECTED_ALG);
        }

        @Override
        public JCAContext getJCAContext() {
            return jcaContext;
        }
    }
}
