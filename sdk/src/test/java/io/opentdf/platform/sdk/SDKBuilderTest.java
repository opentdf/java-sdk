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
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.RewrapRequest;
import io.opentdf.platform.kas.RewrapResponse;
import io.opentdf.platform.policy.namespaces.GetNamespaceRequest;
import io.opentdf.platform.policy.namespaces.GetNamespaceResponse;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;


public class SDKBuilderTest {

    @Test
    void testCreatingSDKServices() throws IOException, InterruptedException {
        Server platformServicesServer = null;
        Server kasServer = null;
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

            // this service returns the platform_issuer url to the SDK during bootstrapping. This
            // tells the SDK where to download the OIDC discovery document from (our test webserver!)
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

            // remember the auth headers that we received during GRPC calls to platform services
            AtomicReference<String> servicesAuthHeader = new AtomicReference<>(null);
            AtomicReference<String> servicesDPoPHeader = new AtomicReference<>(null);

            // remember the auth headers that we received during GRPC calls to KAS
            AtomicReference<String> kasAuthHeader = new AtomicReference<>(null);
            AtomicReference<String> kasDPoPHeader = new AtomicReference<>(null);
            // we use the server in two different ways. the first time we use it to actually return
            // issuer for bootstrapping. the second time we use the interception functionality in order
            // to make sure that we are including a DPoP proof and an auth header
            platformServicesServer = ServerBuilder
                    .forPort(getRandomPort())
                    .directExecutor()
                    .addService(wellKnownService)
                    .addService(new NamespaceServiceGrpc.NamespaceServiceImplBase() {})
                    .intercept(new ServerInterceptor() {
                        @Override
                        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                            servicesAuthHeader.set(headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER)));
                            servicesDPoPHeader.set(headers.get(Metadata.Key.of("DPoP", Metadata.ASCII_STRING_MARSHALLER)));
                            return next.startCall(call, headers);
                        }
                    })
                    .build()
                    .start();


            kasServer = ServerBuilder
                    .forPort(getRandomPort())
                    .directExecutor()
                    .addService(new AccessServiceGrpc.AccessServiceImplBase() {
                        @Override
                        public void rewrap(RewrapRequest request, StreamObserver<RewrapResponse> responseObserver) {
                            responseObserver.onNext(RewrapResponse.getDefaultInstance());
                            responseObserver.onCompleted();
                        }
                    })
                    .intercept(new ServerInterceptor() {
                        @Override
                        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                            kasAuthHeader.set(headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER)));
                            kasDPoPHeader.set(headers.get(Metadata.Key.of("DPoP", Metadata.ASCII_STRING_MARSHALLER)));
                            return next.startCall(call, headers);
                        }
                    })
                    .build()
                    .start();

            SDK.Services services = SDKBuilder
                    .newBuilder()
                    .clientSecret("client-id", "client-secret")
                    .platformEndpoint("localhost:" + platformServicesServer.getPort())
                    .useInsecurePlaintextConnection(true)
                    .buildServices();

            assertThat(services).isNotNull();

            httpServer.enqueue(new MockResponse()
                    .setBody("{\"access_token\": \"hereisthetoken\", \"token_type\": \"Bearer\"}")
                    .setHeader("Content-Type", "application/json"));

            var ignored = services.namespaces().getNamespace(GetNamespaceRequest.getDefaultInstance());

            // we've now made two requests. one to get the bootstrapping info and one
            // call that should activate the token fetching logic
            assertThat(httpServer.getRequestCount()).isEqualTo(2);

            httpServer.takeRequest();

            // validate that we made a reasonable request to our fake IdP to get an access token
            var accessTokenRequest = httpServer.takeRequest();
            assertThat(accessTokenRequest).isNotNull();
            var authHeader = accessTokenRequest.getHeader("Authorization");
            assertThat(authHeader).isNotNull();
            var authHeaderParts = authHeader.split(" ");
            assertThat(authHeaderParts).hasSize(2);
            assertThat(authHeaderParts[0]).isEqualTo("Basic");
            var usernameAndPassword = new String(Base64.getDecoder().decode(authHeaderParts[1]), StandardCharsets.UTF_8);
            assertThat(usernameAndPassword).isEqualTo("client-id:client-secret");

            // validate that during the request to the namespace service we supplied a valid token
            assertThat(servicesDPoPHeader.get()).isNotNull();
            assertThat(servicesAuthHeader.get()).isEqualTo("DPoP hereisthetoken");

            var body = new String(accessTokenRequest.getBody().readByteArray(), StandardCharsets.UTF_8);
            assertThat(body).contains("grant_type=client_credentials");

            // now call KAS _on a different server_ and make sure that the interceptors provide us with auth tokens
            int kasPort = kasServer.getPort();
            SDK.KASInfo kasInfo = () -> "localhost:" + kasPort;
            services.kas().unwrap(kasInfo, new SDK.Policy() {});

            assertThat(kasDPoPHeader.get()).isNotNull();
            assertThat(kasAuthHeader.get()).isEqualTo("DPoP hereisthetoken");
        } finally {
            if (platformServicesServer != null) {
                platformServicesServer.shutdownNow();
            }
            if (kasServer != null) {
                kasServer.shutdownNow();
            }
        }
    }

    private static int getRandomPort() throws IOException {
        int randomPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            randomPort = socket.getLocalPort();
        }
        return randomPort;
    }
}
