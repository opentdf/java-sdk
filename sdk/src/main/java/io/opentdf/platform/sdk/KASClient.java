package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import io.grpc.Channel;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.RewrapRequest;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Date;
import java.util.function.Function;

public class KASClient implements SDK.KAS {
    private final Function<String, Channel> channelMaker;
    private final RSAKeyPair signingKeypair;
    private final RSAKeyPair encryptionKeypair;

    public KASClient(Function<String, Channel> channelMaker, RSAKeyPair signingKeypair) {
        this.channelMaker = channelMaker;
        this.encryptionKeypair = new RSAKeyPair();
        this.signingKeypair = signingKeypair;
    }

    @Override
    public String getPublicKey(URI uri) {
        Channel channel = channelMaker.apply(uri.toString());
        return AccessServiceGrpc
                .newBlockingStub(channel)
                .publicKey(PublicKeyRequest.getDefaultInstance())
                .getPublicKey();
    }

    private static class RewrapRequestBody {
        String policy;
        String clientPublicKey;
    }
    @Override
    public byte[] unwrap(URI uri, String policy) {
        Channel channel = channelMaker.apply(uri.toString());
        RewrapRequestBody body = new RewrapRequestBody();
        body.policy = policy;
        body.clientPublicKey = encryptionKeypair.publicKeyPEM();

        var claims = new JWTClaimsSet.Builder()
                // TODO: fix this when we have JSON serialization integrated
                .claim("requestBody", body.toString())
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
                .build();

        var jws = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT jwt = new SignedJWT(jws, claims);
        try {
            jwt.sign(signingKeypair.getSigner());
        } catch (JOSEException e) {
            throw new SDKException("error signing KAS request", e);
        }

        RewrapRequest request = RewrapRequest.newBuilder()
                        .setSignedRequestToken(jwt.serialize())
                        .build();
        var response = AccessServiceGrpc.newBlockingStub(channel).rewrap(request);
        return response.getEntityWrappedKey().toByteArray();
    }
}
