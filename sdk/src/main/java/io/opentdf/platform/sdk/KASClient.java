package io.opentdf.platform.sdk;

import com.google.gson.Gson;
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
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusException;
import io.grpc.StatusRuntimeException;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.RewrapRequest;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

public class KASClient implements SDK.KAS {
    // this exists to allow some customization per-kas
    private final Function<String, ManagedChannelBuilder<?>> channelMaker;
    private final RSAKeyPair signingKeypair;
    private final RSAKeyPair encryptionKeypair;

    private final HashMap<String, Channel> channels = new HashMap<>();

    public KASClient(Function<String, ManagedChannelBuilder<?>> channelMaker, RSAKeyPair signingKeypair) {
        this.channelMaker = channelMaker;
        this.encryptionKeypair = new RSAKeyPair();
        this.signingKeypair = signingKeypair;
    }

    private synchronized Channel getChannel(String uri) {
        if (!channels.containsKey(uri)) {
            channels.put(uri, channelMaker.apply(uri).build());
        }

        return channels.get(uri);
    }

    @Override
    public String getPublicKey(Config.KASInfo kasInfo) {
        Channel channel = getChannel(kasInfo.URL);
        try {
            return AccessServiceGrpc
                    .newBlockingStub(channel)
                    .publicKey(PublicKeyRequest.getDefaultInstance())
                    .getPublicKey();
        } catch (StatusRuntimeException e) {

        }
    }

    private static class RewrapRequestBody {
        String policy;
        String clientPublicKey;
    }

    final private Gson gson = new Gson();
    @Override
    public byte[] unwrap(Config.KASInfo kasInfo, PolicyObject policy) {
        Channel channel = channelMaker.apply(kasInfo.URL).build();
        RewrapRequestBody body = new RewrapRequestBody();
        body.policy = gson.toJson(policy);
        body.clientPublicKey = encryptionKeypair.publicKeyPEM();

        var claims = new JWTClaimsSet.Builder()
                // TODO: fix this when we have JSON serialization integrated
                .claim("requestBody", gson.toJson(body))
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
        var encryptedKey = response.getEntityWrappedKey().toByteArray();

        try {
            return encryptionKeypair.getAsymDecryption().decrypt(encryptedKey);
        } catch (Exception e) {
            throw new SDKException("Error decrypting wrapped key", e);
        }
    }
}
