package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import io.grpc.Channel;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.RewrapRequest;
import org.checkerframework.checker.units.qual.A;

import java.net.URI;
import java.util.function.Function;

public class KASClient implements SDK.KAS {
    private final Function<String, Channel> channelMaker;
    private final DPoPProofFactory proofFactory;
    private final AsymDecryption asymDecryption;
    public KASClient(Function<String, Channel> channelMaker, DPoPProofFactory proofFactory, RSAKey key) {
        this.channelMaker = channelMaker;
        this.proofFactory = proofFactory;
        byte[] publicPEM;
        byte[] privatePEM;
        try {
            publicPEM = key.toPublicKey().getEncoded();
            privatePEM = key.toPrivateKey().getEncoded();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        asymDecryption = new AsymDecryption(privatePEM);
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
        Manifest.KeyAccess keyAccess;
        String clientPublicKey;
    }
    @Override
    public String unwrap(URI uri, Manifest.KeyAccess keyAccess, String policy) {
//        Channel channel = channelMaker.apply(uri.toString());
//        RewrapRequestBody body = new RewrapRequestBody();
//        body.policy = policy;
//        body.keyAccess = keyAccess;
//        body.clientPublicKey =
//
//
//        RewrapRequest request = RewrapRequest.newBuilder()
//                        .setSignedRequestToken()
//                                .set
//        AccessServiceGrpc.newBlockingStub(channel).rewrap()
        return null;
    }
}
