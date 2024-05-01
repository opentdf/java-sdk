package io.opentdf.platform.sdk;

import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.stub.StreamObserver;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;


public class SDKBuilderTest {

    @Test
    void testCreatingSDKChannel() throws IOException, InterruptedException {
        Server wellknownServer = null;
        // we use the HTTP server for two things:
        // * it returns the OIDC configuration we use at bootstrapping time
        // * it fakes out being an IDP and returns an access token when need to retrieve an access token
        try (MockWebServer httpServer = new MockWebServer()) {
            String oidcConfig;
            try (var in = SDKBuilderTest.class.getResourceAsStream("/oidc-config.json")) {
                oidcConfig = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            String issuer = httpServer.url("my_realm").toString();
            oidcConfig = oidcConfig
                    // if we don't do this then the library code complains that the issuer is wrong
                    .replace("<issuer>", issuer)
                    // we want this server to be called when we fetch an access token during a service call
                    .replace("<token_endpoint>", httpServer.url("tokens").toString());
            httpServer.enqueue(new MockResponse()
                    .setBody(oidcConfig)
                    .setHeader("Content-type", "application/json")
            );

            WellKnownServiceGrpc.WellKnownServiceImplBase wellKnownService = new WellKnownServiceGrpc.WellKnownServiceImplBase() {
                @Override
                public void getWellKnownConfiguration(GetWellKnownConfigurationRequest request, StreamObserver<GetWellKnownConfigurationResponse> responseObserver) {
                    var val = Value.newBuilder().setStringValue(issuer).build();
                    var config = Struct.newBuilder().putFields("platform_issuer", val).build();
                    var response = GetWellKnownConfigurationResponse
                            .newBuilder()
                            .setConfiguration(config)
                            .build();
                    responseObserver.onNext(response);
                    responseObserver.onCompleted();
                }
            };

            AtomicReference<String> authHeaderFromRequest = new AtomicReference<>(null);
            AtomicReference<String> dpopHeaderFromRequest = new AtomicReference<>(null);

            // we use the server in two different ways. the first time we use it to actually return
            // issuer for bootstrapping. the second time we use the interception functionality in order
            // to make sure that we are including a DPoP proof and an auth header
            int randomPort;
            try (ServerSocket socket = new ServerSocket(0)) {
                randomPort = socket.getLocalPort();
            }
            wellknownServer = ServerBuilder
                    .forPort(randomPort)
                    .directExecutor()
                    .addService(wellKnownService)
                    .intercept(new ServerInterceptor() {
                        @Override
                        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                            authHeaderFromRequest.set(headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER)));
                            dpopHeaderFromRequest.set(headers.get(Metadata.Key.of("DPoP", Metadata.ASCII_STRING_MARSHALLER)));
                            return next.startCall(call, headers);
                        }
                    })
                    .build()
                    .start();

            ManagedChannel channel = SDKBuilder
                    .newBuilder()
                    .clientSecret("client-id", "client-secret")
                    .platformEndpoint("localhost:" + wellknownServer.getPort())
                    .useInsecurePlaintextConnection(true)
                    .buildChannel();

            assertThat(channel).isNotNull();
            assertThat(channel.getState(false)).isEqualTo(ConnectivityState.IDLE);

            var wellKnownStub = WellKnownServiceGrpc.newBlockingStub(channel);

            httpServer.enqueue(new MockResponse()
                    .setBody("{\"access_token\": \"hereisthetoken\", \"token_type\": \"Bearer\"}")
                    .setHeader("Content-Type", "application/json"));

            var ignored = wellKnownStub.getWellKnownConfiguration(GetWellKnownConfigurationRequest.getDefaultInstance());
            channel.shutdownNow();

            // we've now made two requests. one to get the bootstrapping info and one
            // call that should activate the token fetching logic
            assertThat(httpServer.getRequestCount()).isEqualTo(2);

            httpServer.takeRequest();
            var accessTokenRequest = httpServer.takeRequest();
            assertThat(accessTokenRequest).isNotNull();
            var authHeader = accessTokenRequest.getHeader("Authorization");
            assertThat(authHeader).isNotNull();
            var authHeaderParts = authHeader.split(" ");
            assertThat(authHeaderParts).hasSize(2);
            assertThat(authHeaderParts[0]).isEqualTo("Basic");
            var usernameAndPassword = new String(Base64.getDecoder().decode(authHeaderParts[1]), StandardCharsets.UTF_8);
            assertThat(usernameAndPassword).isEqualTo("client-id:client-secret");

            assertThat(dpopHeaderFromRequest.get()).isNotNull();
            assertThat(authHeaderFromRequest.get()).isEqualTo("DPoP hereisthetoken");

            var body = new String(accessTokenRequest.getBody().readByteArray(), StandardCharsets.UTF_8);
            assertThat(body).contains("grant_type=client_credentials");

        } finally {
            if (wellknownServer != null) {
                wellknownServer.shutdownNow();
            }
        }
    }
}
