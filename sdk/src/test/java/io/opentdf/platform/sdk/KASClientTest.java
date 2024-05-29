package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.PublicKeyResponse;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.kas.RewrapResponse;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Random;
import java.util.function.Function;

import static io.opentdf.platform.sdk.SDKBuilderTest.getRandomPort;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class KASClientTest {

    private static final Function<String, ManagedChannel> channelFactory = (String url) -> ManagedChannelBuilder
            .forTarget(url)
            .usePlaintext()
            .build();

    @Test
    void testGettingPublicKey() throws IOException {
        AccessServiceGrpc.AccessServiceImplBase accessService = new AccessServiceGrpc.AccessServiceImplBase() {
            @Override
            public void publicKey(PublicKeyRequest request, StreamObserver<PublicKeyResponse> responseObserver) {
                var response = PublicKeyResponse.newBuilder().setPublicKey("тај је клуц").build();
                responseObserver.onNext(response);
                responseObserver.onCompleted();
            }
        };

        Server rewrapServer = null;
        try {
            rewrapServer = startServer(accessService);
            Function<String, ManagedChannel> channelFactory = (String url) -> ManagedChannelBuilder
                    .forTarget(url)
                    .usePlaintext()
                    .build();

            var keypair = CryptoUtils.generateRSAKeypair();
            var dpopKey = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).privateKey(keypair.getPrivate()).build();
            try (var kas = new KASClient(channelFactory, dpopKey)) {
                Config.KASInfo kasInfo = new Config.KASInfo();
                kasInfo.URL = "localhost:" + rewrapServer.getPort();
                assertThat(kas.getPublicKey(kasInfo)).isEqualTo("тај је клуц");
            }
        } finally {
            if (rewrapServer != null) {
                rewrapServer.shutdownNow();
            }
        }
    }

    @Test
    void testCallingRewrap() throws IOException {
        var dpopKeypair = CryptoUtils.generateRSAKeypair();
        var dpopKey = new RSAKey.Builder((RSAPublicKey)dpopKeypair.getPublic()).privateKey(dpopKeypair.getPrivate()).build();
        var serverKeypair = CryptoUtils.generateRSAKeypair();
        AccessServiceGrpc.AccessServiceImplBase accessService = new AccessServiceGrpc.AccessServiceImplBase() {
            @Override
            public void rewrap(RewrapRequest request, StreamObserver<RewrapResponse> responseObserver) {
                SignedJWT signedJWT;
                try {
                    signedJWT = SignedJWT.parse(request.getSignedRequestToken());
                    JWSVerifier verifier = new RSASSAVerifier(dpopKey);
                    if (!signedJWT.verify(verifier)) {
                        responseObserver.onError(new JOSEException("Unable to verify signature"));
                        responseObserver.onCompleted();
                        return;
                    }
                } catch (JOSEException | ParseException e) {
                    responseObserver.onError(e);
                    responseObserver.onCompleted();
                    return;
                }

                String requestBodyJson;
                try {
                    requestBodyJson = signedJWT.getJWTClaimsSet().getStringClaim("requestBody");
                } catch (ParseException e) {
                    responseObserver.onError(e);
                    responseObserver.onCompleted();
                    return;
                }

                var gson = new Gson();
                var req = gson.fromJson(requestBodyJson, KASClient.RewrapRequestBody.class);

                var decryptedKey = new AsymDecryption(serverKeypair.getPrivate()).decrypt(Base64.getDecoder().decode(req.keyAccess.wrappedKey));
                var encryptedKey = new AsymEncryption(req.clientPublicKey).encrypt(decryptedKey);

                responseObserver.onNext(RewrapResponse.newBuilder().setEntityWrappedKey(ByteString.copyFrom(encryptedKey)).build());
                responseObserver.onCompleted();
            }
        };

        Server rewrapServer = null;
        try {
            rewrapServer = startServer(accessService);
            byte[] plaintextKey;
            byte[] rewrapResponse;
            try (var kas = new KASClient(channelFactory, dpopKey)) {

                Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
                keyAccess.url = "localhost:" + rewrapServer.getPort();
                plaintextKey = new byte[32];
                new Random().nextBytes(plaintextKey);
                var serverWrappedKey = new AsymEncryption(serverKeypair.getPublic()).encrypt(plaintextKey);
                keyAccess.wrappedKey = Base64.getEncoder().encodeToString(serverWrappedKey);

                rewrapResponse = kas.unwrap(keyAccess, "the policy");
            }
            assertThat(rewrapResponse).containsExactly(plaintextKey);
        } finally {
            if (rewrapServer != null) {
                rewrapServer.shutdownNow();
            }
        }
    }

    private static Server startServer(AccessServiceGrpc.AccessServiceImplBase accessService) throws IOException {
        return ServerBuilder
                .forPort(getRandomPort())
                .directExecutor()
                .addService(accessService)
                .build()
                .start();
    }
}
