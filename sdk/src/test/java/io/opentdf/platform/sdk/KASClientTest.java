package io.opentdf.platform.sdk;

import com.connectrpc.ProtocolClientConfig;
import com.connectrpc.extensions.GoogleJavaProtobufStrategy;
import com.connectrpc.impl.ProtocolClient;
import com.connectrpc.okhttp.ConnectOkHttpClient;
import com.connectrpc.protocols.GETConfiguration;
import com.connectrpc.protocols.NetworkProtocol;
import com.google.gson.Gson;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.PublicKeyResponse;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.kas.RewrapResponse;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.nio.charset.StandardCharsets;

import static io.opentdf.platform.sdk.SDKBuilderTest.getRandomPort;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class KASClientTest {
    OkHttpClient httpClient = new OkHttpClient.Builder()
            .protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE))
            .build();

    BiFunction<OkHttpClient, String, ProtocolClient> aclientFactory = (OkHttpClient client, String endpoint) -> {
        return new ProtocolClient(
                new ConnectOkHttpClient(httpClient),
                new ProtocolClientConfig(endpoint, new GoogleJavaProtobufStrategy(), ProtocolType.GRPC.getNetworkProtocol(), null, GETConfiguration.Enabled.INSTANCE)
        );
    };

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


            var keypair = CryptoUtils.generateRSAKeypair();
            var dpopKey = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).privateKey(keypair.getPrivate())
                    .build();
            try (var kas = new KASClient(httpClient, aclientFactory, new DefaultSrtSigner(dpopKey), true)) {
                Config.KASInfo kasInfo = new Config.KASInfo();
                kasInfo.URL = "http://localhost:" + rewrapServer.getPort();
                assertThat(kas.getPublicKey(kasInfo).PublicKey).isEqualTo("тај је клуц");
            }
        } finally {
            if (rewrapServer != null) {
                rewrapServer.shutdownNow();
            }
        }
    }

    @Test
    void testGettingKid() throws IOException {
        AccessServiceGrpc.AccessServiceImplBase accessService = new AccessServiceGrpc.AccessServiceImplBase() {
            @Override
            public void publicKey(PublicKeyRequest request, StreamObserver<PublicKeyResponse> responseObserver) {
                var response = PublicKeyResponse.newBuilder().setKid("r1").build();
                responseObserver.onNext(response);
                responseObserver.onCompleted();
            }
        };

        Server server = null;
        try {
            server = startServer(accessService);

            var keypair = CryptoUtils.generateRSAKeypair();
            var dpopKey = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).privateKey(keypair.getPrivate())
                    .build();
            try (var kas = new KASClient(httpClient, aclientFactory, new DefaultSrtSigner(dpopKey), true)) {
                Config.KASInfo kasInfo = new Config.KASInfo();
                kasInfo.URL = "http://localhost:" + server.getPort();
                assertThat(kas.getPublicKey(kasInfo).KID).isEqualTo("r1");
            } catch (Exception e) {
                throw e;
            }
        } finally {
            if (server != null) {
                server.shutdownNow();
            }
        }
    }

    @Test
    void testCallingRewrap() throws IOException {
        var dpopKeypair = CryptoUtils.generateRSAKeypair();
        var dpopKey = new RSAKey.Builder((RSAPublicKey) dpopKeypair.getPublic()).privateKey(dpopKeypair.getPrivate())
                .build();
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

                var decryptedKey = new AsymDecryption(serverKeypair.getPrivate())
                        .decrypt(Base64.getDecoder().decode(req.keyAccess.wrappedKey));
                var encryptedKey = new AsymEncryption(req.clientPublicKey).encrypt(decryptedKey);

                responseObserver.onNext(
                        RewrapResponse.newBuilder().setEntityWrappedKey(ByteString.copyFrom(encryptedKey)).build());
                responseObserver.onCompleted();
            }
        };

        Server rewrapServer = null;
        try {
            rewrapServer = startServer(accessService);
            byte[] plaintextKey;
            byte[] rewrapResponse;
            try (var kas = new KASClient(httpClient, aclientFactory, new DefaultSrtSigner(dpopKey), true)) {

                Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
                keyAccess.url = "http://localhost:" + rewrapServer.getPort();
                plaintextKey = new byte[32];
                new Random().nextBytes(plaintextKey);
                var serverWrappedKey = new AsymEncryption(serverKeypair.getPublic()).encrypt(plaintextKey);
                keyAccess.wrappedKey = Base64.getEncoder().encodeToString(serverWrappedKey);

                rewrapResponse = kas.unwrap(keyAccess, "the policy", KeyType.RSA2048Key);
            }
            assertThat(rewrapResponse).containsExactly(plaintextKey);
        } finally {
            if (rewrapServer != null) {
                rewrapServer.shutdownNow();
            }
        }
    }

    @Test
    void testCustomSrtSignerIsUsed() throws IOException {
        var serverKeypair = CryptoUtils.generateRSAKeypair();
        var signingInput = new AtomicReference<byte[]>();
        var signedToken = new AtomicReference<String>();
        var signingKeypair = CryptoUtils.generateRSAKeypair();
        var signingKey = new RSAKey.Builder((RSAPublicKey) signingKeypair.getPublic())
                .privateKey(signingKeypair.getPrivate())
                .build();
        SrtSigner srtSigner = new SrtSigner() {
            @Override
            public byte[] sign(byte[] input) {
                signingInput.set(input);
                try {
                    return new RSASSASigner(signingKey)
                            .sign(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), input)
                            .decode();
                } catch (JOSEException e) {
                    throw new AssertionError("Signing failed unexpectedly in test", e);
                }
            }

            @Override
            public String alg() {
                return "RS256";
            }
        };

        AccessServiceGrpc.AccessServiceImplBase accessService = new AccessServiceGrpc.AccessServiceImplBase() {
            @Override
            public void rewrap(RewrapRequest request, StreamObserver<RewrapResponse> responseObserver) {
                signedToken.set(request.getSignedRequestToken());
                SignedJWT signedJWT;
                try {
                    signedJWT = SignedJWT.parse(request.getSignedRequestToken());
                    JWSVerifier verifier = new RSASSAVerifier(new RSAKey.Builder((RSAPublicKey) signingKeypair.getPublic()).build());
                    if (!signedJWT.verify(verifier)) {
                        responseObserver.onError(new JOSEException("Unable to verify signature"));
                        responseObserver.onCompleted();
                        return;
                    }
                } catch (ParseException e) {
                    responseObserver.onError(e);
                    responseObserver.onCompleted();
                    return;
                } catch (JOSEException e) {
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

                byte[] decryptedKey;
                try {
                    decryptedKey = new AsymDecryption(serverKeypair.getPrivate())
                            .decrypt(Base64.getDecoder().decode(req.keyAccess.wrappedKey));
                } catch (Exception e) {
                    responseObserver.onError(e);
                    responseObserver.onCompleted();
                    return;
                }
                var encryptedKey = new AsymEncryption(req.clientPublicKey).encrypt(decryptedKey);

                responseObserver.onNext(
                        RewrapResponse.newBuilder().setEntityWrappedKey(ByteString.copyFrom(encryptedKey)).build());
                responseObserver.onCompleted();
            }
        };

        Server rewrapServer = null;
        try {
            rewrapServer = startServer(accessService);
            byte[] plaintextKey;
            byte[] rewrapResponse;
            try (var kas = new KASClient(httpClient, aclientFactory, srtSigner, true)) {
                Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
                keyAccess.url = "http://localhost:" + rewrapServer.getPort();
                plaintextKey = new byte[32];
                new Random().nextBytes(plaintextKey);
                var serverWrappedKey = new AsymEncryption(serverKeypair.getPublic()).encrypt(plaintextKey);
                keyAccess.wrappedKey = Base64.getEncoder().encodeToString(serverWrappedKey);

                rewrapResponse = kas.unwrap(keyAccess, "the policy", KeyType.RSA2048Key);
            }
            assertThat(rewrapResponse).containsExactly(plaintextKey);
            assertThat(signingInput.get()).isNotNull();
            var tokenParts = signedToken.get().split("\\.", 3);
            assertThat(tokenParts.length).isEqualTo(3);
            var expectedSigningInput = (tokenParts[0] + "." + tokenParts[1]).getBytes(StandardCharsets.US_ASCII);
            assertThat(signingInput.get()).containsExactly(expectedSigningInput);
        } finally {
            if (rewrapServer != null) {
                rewrapServer.shutdownNow();
            }
        }
    }

    @Test
    void testSrtSignerAlgMismatchRejected() {
        SrtSigner srtSigner = new SrtSigner() {
            @Override
            public byte[] sign(byte[] input) {
                return new byte[0];
            }

            @Override
            public String alg() {
                return "none";
            }
        };

        assertThrows(SDKException.class, () -> new KASClient(httpClient, aclientFactory, srtSigner, true));
    }

    @Test
    void testAddressNormalizationWithHTTPSClient() {
        var lastAddress = new AtomicReference<String>();
        var dpopKeypair = CryptoUtils.generateRSAKeypair();
        var dpopKey = new RSAKey.Builder((RSAPublicKey) dpopKeypair.getPublic()).privateKey(dpopKeypair.getPrivate())
                .build();
        var httpsKASClient = new KASClient(httpClient, (client, addr) -> {
            lastAddress.set(addr);
            return aclientFactory.apply(client, addr);
        }, new DefaultSrtSigner(dpopKey), false);

        var stub = httpsKASClient.getStub("http://localhost:8080");
        assertThat(lastAddress.get()).isEqualTo("https://localhost:8080");
        var otherStub = httpsKASClient.getStub("https://localhost:8080");
        assertThat(lastAddress.get()).isEqualTo("https://localhost:8080");
        assertThat(stub).isSameAs(otherStub);
    }

    @Test
    void testAddressNormalizationWithInsecureHTTPClient() {
        var lastAddress = new AtomicReference<String>();
        var dpopKeypair = CryptoUtils.generateRSAKeypair();
        var dpopKey = new RSAKey.Builder((RSAPublicKey) dpopKeypair.getPublic()).privateKey(dpopKeypair.getPrivate())
                .build();
        var httpsKASClient = new KASClient(httpClient, (client, addr) -> {
            lastAddress.set(addr);
            return aclientFactory.apply(client, addr);
        }, new DefaultSrtSigner(dpopKey), true);

        var c1 = httpsKASClient.getStub("http://example.org");
        assertThat(lastAddress.get()).isEqualTo("http://example.org:80");
        var c2 = httpsKASClient.getStub("example.org:80");
        assertThat(lastAddress.get()).isEqualTo("http://example.org:80");
        assertThat(c1).isSameAs(c2);
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
