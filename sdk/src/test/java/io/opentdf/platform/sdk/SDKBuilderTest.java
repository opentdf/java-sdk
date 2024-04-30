package io.opentdf.platform.sdk;

import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;


public class SDKBuilderTest {

    @Test
    void testCreatingSDKWithIssuer() throws IOException {
        Server server = null;
        try (MockWebServer oidcDiscoveryServer = new MockWebServer()) {
            String oidcConfig;
            try (var in = SDKBuilderTest.class.getResourceAsStream("/oidc-config.json")) {
                oidcConfig = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            String issuer = oidcDiscoveryServer.url("my_realm").toString();
            oidcConfig = oidcConfig.replace("<issuer>", issuer);
            oidcDiscoveryServer.enqueue(new MockResponse()
                    .setBody(oidcConfig)
                    .setHeader("Content-type", "application/json")
            );

            WellKnownServiceGrpc.WellKnownServiceImplBase serviceImplBase = new WellKnownServiceGrpc.WellKnownServiceImplBase() {
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

            server = ServerBuilder
                    .forPort(7000 + new Random().nextInt(3000))
                    .directExecutor()
                    .addService(serviceImplBase)
                    .build()
                    .start();

            ManagedChannel channel = SDKBuilder
                    .newBuilder()
                    .withClientSecret("client", "secret")
                    .platformEndpoint("localhost:" + server.getPort())
                    .withPlainTextConnection(true)
                    .buildChannel();

            channel.shutdownNow();

            assertThat(channel).isNotNull();
        } catch (Exception e) {
            if (server != null) {
                server.shutdownNow();
            }

            throw e;
        }
    }
}
