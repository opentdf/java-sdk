package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.ManagedChannel;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.PublicKeyResponse;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.sdk.Autoconfigure.KeySplitStep;
import io.opentdf.platform.sdk.nanotdf.ECKeyPair;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static java.lang.String.format;

public class KASClient implements SDK.KAS, AutoCloseable {

    private final Function<String, ManagedChannel> channelFactory;
    private final RSASSASigner signer;
    private final AsymDecryption decryptor;
    private final String publicKeyPEM;

    private KASKeyCache kasKeyCache;

    /***
     * A client that communicates with KAS
     * @param channelFactory A function that produces channels that can be used to communicate
     * @param dpopKey
     */
    public KASClient(Function <String, ManagedChannel> channelFactory, RSAKey dpopKey) {
        this.channelFactory = channelFactory;
        try {
            this.signer = new RSASSASigner(dpopKey);
        } catch (JOSEException e) {
            throw new SDKException("error creating dpop signer", e);
        }
        var encryptionKeypair = CryptoUtils.generateRSAKeypair();
        decryptor = new AsymDecryption(encryptionKeypair.getPrivate());
        publicKeyPEM = CryptoUtils.getRSAPublicKeyPEM(encryptionKeypair.getPublic());

        this.kasKeyCache = new KASKeyCache();
    }

    @Override
    public String getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
        //String.format("ec:%s", curve.toString())
        return getStub(kasInfo.URL)
                .publicKey(PublicKeyRequest.newBuilder().setAlgorithm(String.format("ec:%s", curve.toString())).build())
                .getPublicKey();
    }

    @Override
    public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
        Config.KASInfo cachedValue = this.kasKeyCache.get(kasInfo.URL, kasInfo.Algorithm);
        if (cachedValue != null) {
            return cachedValue;
        }
        PublicKeyResponse resp = getStub(kasInfo.URL).publicKey(PublicKeyRequest.getDefaultInstance());
        
        var kiCopy = new Config.KASInfo();
        kiCopy.KID = resp.getKid();
        kiCopy.PublicKey = resp.getPublicKey();
        kiCopy.URL = kasInfo.URL;

        this.kasKeyCache.store(kiCopy);
        return kiCopy;
    }

    // @Override
    // public String getKid(Config.KASInfo kasInfo) {
    //     return getStub(kasInfo.URL)
    //             .publicKey(PublicKeyRequest.getDefaultInstance())
    //             .getKid();
    // }

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
        for (var entry: entries) {
            entry.channel.shutdownNow();
        }
    }

    class TimeStampedKASInfo {
        Config.KASInfo kasInfo;
        LocalDateTime timestamp;

        public TimeStampedKASInfo(Config.KASInfo kasInfo, LocalDateTime timestamp) {
            this.kasInfo = kasInfo;
            this.timestamp = timestamp;
        }
    }

    class KASKeyRequest {
        private String url;
        private String algorithm;
    
        public KASKeyRequest(String url, String algorithm) {
            this.url = url;
            this.algorithm = algorithm;
        }
    
        // Override equals and hashCode to ensure proper functioning of the HashMap
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || !(o instanceof KASKeyRequest)) return false;
            KASKeyRequest that = (KASKeyRequest) o;
           if (algorithm == null){
                return url.equals(that.url);
            }
            return url.equals(that.url) && algorithm.equals(that.algorithm);
        }
    
        @Override
        public int hashCode() {
            int result = 31 * url.hashCode();
            if (algorithm != null) {
                result = result + algorithm.hashCode();
            }
            return result;
        }
    }

    class KASKeyCache {
        private Map<KASKeyRequest, TimeStampedKASInfo> cache;

        public KASKeyCache() {
            this.cache = new HashMap<>();
        }

        public void clear() {
            this.cache = new HashMap<>();
        }

        public Config.KASInfo get(String url, String algorithm) {
            KASKeyRequest cacheKey = new KASKeyRequest(url, algorithm);
            LocalDateTime now = LocalDateTime.now();
            TimeStampedKASInfo cachedValue = cache.get(cacheKey);

            if (cachedValue == null) {
                return null;
            }

            LocalDateTime anHourAgo = now.minus(1, ChronoUnit.HOURS);
            if (anHourAgo.isAfter(cachedValue.timestamp)) {
                cache.remove(cacheKey);
                return null;
            }

            return cachedValue.kasInfo;
        }

        public void store(Config.KASInfo kasInfo) {
            KASKeyRequest cacheKey = new KASKeyRequest(kasInfo.URL, kasInfo.Algorithm);
            cache.put(cacheKey, new TimeStampedKASInfo(kasInfo, LocalDateTime.now()));
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
    public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy) {
        RewrapRequestBody body = new RewrapRequestBody();
        body.policy = policy;
        body.clientPublicKey = publicKeyPEM;
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
        return decryptor.decrypt(wrappedKey);
    }

    public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL)  {
        ECKeyPair keyPair = new ECKeyPair(curve.toString(), ECKeyPair.ECAlgorithm.ECDH);

        NanoTDFKeyAccess keyAccess = new NanoTDFKeyAccess();
        keyAccess.header = header;
        keyAccess.type = "remote";
        keyAccess.url = kasURL;
        keyAccess.protocol = "kas";

        NanoTDFRewrapRequestBody body = new NanoTDFRewrapRequestBody();
        body.algorithm = String.format("ec:%s", curve.toString());
        body.clientPublicKey =  keyPair.publicKeyInPEMFormat();
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

