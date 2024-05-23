package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.Channel;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.RewrapRequest;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

public class KASClient implements SDK.KAS {

    private final Function<String, Channel> channelFactory;
    private final RSASSASigner signer;

    private final AsymEncryption encryptor;
    private final AsymDecryption decryptor;

    private final String publicKeyPEM;

    public KASClient(Function <String, Channel> channelFactory, RSAKey key) {
        this.channelFactory = channelFactory;
        try {
            this.signer = new RSASSASigner(key);
        } catch (JOSEException e) {
            throw new SDKException("error creating dpop signer", e);
        }
        var keypair = CryptoUtils.generateRSAKeypair();
        encryptor = new AsymEncryption(keypair.getPublic());
        decryptor = new AsymDecryption(keypair.getPrivate());
        publicKeyPEM = CryptoUtils.getRSAPublicKeyPEM(keypair.getPublic());
    }

    @Override
    public String getPublicKey(Config.KASInfo kasInfo) {
        return getStub(kasInfo.URL)
                .publicKey(PublicKeyRequest.getDefaultInstance())
                .getPublicKey();
    }

    private static class RewrapRequestBody {
        String policy;
        String clientPublicKey;

        Manifest.KeyAccess keyAccess;
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
                // TODO: fix this when we have JSON serialization integrated
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

    private final HashMap<String, AccessServiceGrpc.AccessServiceBlockingStub> stubs = new HashMap<>();

    private synchronized AccessServiceGrpc.AccessServiceBlockingStub getStub(String url) {
        if (!stubs.containsKey(url)) {
            var channel = channelFactory.apply(url);
            var stub = AccessServiceGrpc.newBlockingStub(channel);
            stubs.put(url, stub);
        }

        return stubs.get(url);
    }
}
