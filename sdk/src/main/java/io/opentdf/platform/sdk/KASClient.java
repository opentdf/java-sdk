package io.opentdf.platform.sdk;

import com.connectrpc.Code;
import com.connectrpc.ConnectException;
import com.connectrpc.impl.ProtocolClient;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.opentdf.platform.kas.AccessServiceClient;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.PublicKeyResponse;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.kas.RewrapResponse;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.SDK.KasBadRequestException;

import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
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
    private final RSASSASigner signer;
    private AsymDecryption decryptor;
    private String clientPublicKey;
    private KASKeyCache kasKeyCache;

    private static final Logger log = LoggerFactory.getLogger(KASClient.class);

    /***
     * A client that communicates with KAS
     * 
     *                       communicate
     * @param dpopKey
     */
    KASClient(OkHttpClient httpClient, BiFunction<OkHttpClient, String, ProtocolClient> protocolClientFactory, RSAKey dpopKey, boolean usePlaintext) {
        this.httpClient = httpClient;
        this.protocolClientFactory = protocolClientFactory;
        this.usePlaintext = usePlaintext;
        try {
            this.signer = new RSASSASigner(dpopKey);
        } catch (JOSEException e) {
            throw new SDKException("error creating dpop signer", e);
        }
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

    @Override
    public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy,  KeyType sessionKeyType) {
        ECKeyPair ecKeyPair = null;
        if (sessionKeyType.isEc()) {
            var curve = sessionKeyType.getECCurve();
            ecKeyPair = new ECKeyPair(curve, ECKeyPair.ECAlgorithm.ECDH);
            clientPublicKey = ecKeyPair.publicKeyInPEMFormat();
        } else {
            // Initialize the RSA key pair only once and reuse it for future unwrap operations
            if (decryptor == null) {
                var encryptionKeypair = CryptoUtils.generateRSAKeypair();
                decryptor = new AsymDecryption(encryptionKeypair.getPrivate());
                clientPublicKey = CryptoUtils.getRSAPublicKeyPEM(encryptionKeypair.getPublic());
            }
        }

        RewrapRequestBody body = new RewrapRequestBody();
        body.policy = policy;
        body.clientPublicKey = clientPublicKey;
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
        if (sessionKeyType.isEc()) {

            if (ecKeyPair == null) {
                throw new SDKException("ECKeyPair is null. Unable to proceed with the unwrap operation.");
            }

            var kasEphemeralPublicKey = response.getSessionPublicKey();
            var publicKey = ECKeyPair.publicKeyFromPem(kasEphemeralPublicKey);
            byte[] symKey = ECKeyPair.computeECDHKey(publicKey, ecKeyPair.getPrivateKey());

            var sessionKey = ECKeyPair.calculateHKDF(GLOBAL_KEY_SALT, symKey);

            AesGcm gcm = new AesGcm(sessionKey);
            AesGcm.Encrypted encrypted = new AesGcm.Encrypted(wrappedKey);
            return gcm.decrypt(encrypted);
        } else {
            return decryptor.decrypt(wrappedKey);
        }
    }

    private final HashMap<String, AccessServiceClient> stubs = new HashMap<>();

    // make this protected so we can test the address normalization logic
    synchronized AccessServiceClient getStub(String url) {
        return stubs.computeIfAbsent(AddressNormalizer.normalizeAddress(url, usePlaintext), (String address) -> {
            var client = protocolClientFactory.apply(httpClient, address);
            return new AccessServiceClient(client);
        });
    }
}
