package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.Status;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.PublicKeyResponse;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.kas.RewrapResponse;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.nanotdf.ECKeyPair;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import io.opentdf.platform.sdk.TDF.KasBadRequestException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import static io.opentdf.platform.sdk.TDF.GLOBAL_KEY_SALT;
import static java.lang.String.format;

/**
 * A client implementation that communicates with a Key Access Service (KAS).
 * This class provides methods to retrieve public keys, unwrap encrypted keys,
 * and manage key caches.
 */
public class KASClient implements SDK.KAS {

    private final Function<String, ManagedChannel> channelFactory;
    private final RSASSASigner signer;
    private AsymDecryption decryptor;
    private String clientPublicKey;
    private KASKeyCache kasKeyCache;

    /***
     * A client that communicates with KAS
     * 
     * @param channelFactory A function that produces channels that can be used to
     *                       communicate
     * @param dpopKey
     */
    public KASClient(Function<String, ManagedChannel> channelFactory, RSAKey dpopKey) {
        this.channelFactory = channelFactory;
        try {
            this.signer = new RSASSASigner(dpopKey);
        } catch (JOSEException e) {
            throw new SDKException("error creating dpop signer", e);
        }
        this.kasKeyCache = new KASKeyCache();
    }

    @Override
    public KASInfo getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
        var r = getStub(kasInfo.URL)
                .publicKey(
                        PublicKeyRequest.newBuilder().setAlgorithm(String.format("ec:%s", curve.toString())).build());
        var k2 = kasInfo.clone();
        k2.KID = r.getKid();
        k2.PublicKey = r.getPublicKey();
        return k2;
    }

    @Override
    public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
        Config.KASInfo cachedValue = this.kasKeyCache.get(kasInfo.URL, kasInfo.Algorithm);
        if (cachedValue != null) {
            return cachedValue;
        }

        PublicKeyRequest request = (kasInfo.Algorithm == null || kasInfo.Algorithm.isEmpty())
                ? PublicKeyRequest.getDefaultInstance()
                : PublicKeyRequest.newBuilder().setAlgorithm(kasInfo.Algorithm).build();

        PublicKeyResponse resp = getStub(kasInfo.URL).publicKey(request);

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

    private String normalizeAddress(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            // if there is no protocol then they either gave us
            // a correct address or one we don't know how to fix
            return urlString;
        }

        // otherwise we take the specified port or default
        // based on whether the URL uses a scheme that
        // implies TLS
        int port;
        if (url.getPort() == -1) {
            if ("http".equals(url.getProtocol())) {
                port = 80;
            } else {
                port = 443;
            }
        } else {
            port = url.getPort();
        }

        return format("%s:%d", url.getHost(), port);
    }

    @Override
    public synchronized void close() {
        var entries = new ArrayList<>(stubs.values());
        stubs.clear();
        for (var entry : entries) {
            entry.channel.shutdownNow();
        }
    }

    static class RewrapRequestBody {
        String policy;
        String clientPublicKey;
        Manifest.KeyAccess keyAccess;
    }

    static class NanoTDFKeyAccess {
        String header;
        String type;
        String url;
        String protocol;
    }

    static class NanoTDFRewrapRequestBody {
        String algorithm;
        String clientPublicKey;
        NanoTDFKeyAccess keyAccess;
    }

    private static final Gson gson = new Gson();

    @Override
    public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy,  KeyType sessionKeyType) {
        ECKeyPair ecKeyPair = null;
        
        if (sessionKeyType.isEc()) {
            var curveName = sessionKeyType.getCurveName();
            ecKeyPair = new ECKeyPair(curveName, ECKeyPair.ECAlgorithm.ECDH);
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
        try {
            response = getStub(keyAccess.url).rewrap(request);
            var wrappedKey = response.getEntityWrappedKey().toByteArray();
            if (sessionKeyType != KeyType.RSA2048Key) {

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
        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.INVALID_ARGUMENT) {
                // 400 Bad Request
                throw new KasBadRequestException("rewrap request 400: " + e.toString());
            }
            throw e;
        }
        
    }

    public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {
        ECKeyPair keyPair = new ECKeyPair(curve.toString(), ECKeyPair.ECAlgorithm.ECDH);

        NanoTDFKeyAccess keyAccess = new NanoTDFKeyAccess();
        keyAccess.header = header;
        keyAccess.type = "remote";
        keyAccess.url = kasURL;
        keyAccess.protocol = "kas";

        NanoTDFRewrapRequestBody body = new NanoTDFRewrapRequestBody();
        body.algorithm = String.format("ec:%s", curve.toString());
        body.clientPublicKey = keyPair.publicKeyInPEMFormat();
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

        var response = getStub(keyAccess.url).rewrap(request);
        var wrappedKey = response.getEntityWrappedKey().toByteArray();

        // Generate symmetric key
        byte[] symmetricKey = ECKeyPair.computeECDHKey(ECKeyPair.publicKeyFromPem(response.getSessionPublicKey()),
                keyPair.getPrivateKey());

        // Generate HKDF key
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error creating SHA-256 message digest", e);
        }
        byte[] hashOfSalt = digest.digest(NanoTDF.MAGIC_NUMBER_AND_VERSION);
        byte[] key = ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);

        AesGcm gcm = new AesGcm(key);
        AesGcm.Encrypted encrypted = new AesGcm.Encrypted(wrappedKey);
        return gcm.decrypt(encrypted);
    }

    private final HashMap<String, CacheEntry> stubs = new HashMap<>();

    private static class CacheEntry {
        final ManagedChannel channel;
        final AccessServiceGrpc.AccessServiceBlockingStub stub;

        private CacheEntry(ManagedChannel channel, AccessServiceGrpc.AccessServiceBlockingStub stub) {
            this.channel = channel;
            this.stub = stub;
        }
    }

    // make this protected so we can test the address normalization logic
    synchronized AccessServiceGrpc.AccessServiceBlockingStub getStub(String url) {
        var realAddress = normalizeAddress(url);
        if (!stubs.containsKey(realAddress)) {
            var channel = channelFactory.apply(realAddress);
            var stub = AccessServiceGrpc.newBlockingStub(channel);
            stubs.put(realAddress, new CacheEntry(channel, stub));
        }

        return stubs.get(realAddress).stub;
    }
}
