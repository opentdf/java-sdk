package io.opentdf.platform.sdk;

import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.StatusRuntimeException;
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
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.pem.util.PemUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;


public class SDKBuilderTest {

    final String EXAMPLE_COM_PEM= "-----BEGIN CERTIFICATE-----\n" +
            "MIIBqTCCARKgAwIBAgIIT0xFd/5uogEwDQYJKoZIhvcNAQEFBQAwFjEUMBIGA1UEAxMLZXhhbXBs\n" +
            "ZS5jb20wIBcNMTcwMTIwMTczOTIwWhgPOTk5OTEyMzEyMzU5NTlaMBYxFDASBgNVBAMTC2V4YW1w\n" +
            "bGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2Tl2MdaUFmjAaYwmEwgEVRfVqwJO4\n" +
            "Y+7Vxm4UqQRKNucpGUwUBo9FSvuQACpnJwHsK2WhiuSpVkunhmSx5Qb4KVSH2RT2vHBUsA3t12S2\n" +
            "1Vkskiya3E7QR91zZGVxZyB4gSBVhvSVXeP9+RogLLziki/VDXXKT4TIuyML1eUQ2QIDAQABMA0G\n" +
            "CSqGSIb3DQEBBQUAA4GBAGfw0xavZSJXxuFAwxCZBtne9BAtk+SmfKkTI21v8Tx6w/p5Yt0IIvF3\n" +
            "0wCES7YVZ+zUc8vtVVyk1q3f1ZqXqVvzRCjzLzQnu6VVLBaiZPH9SYNX6j0pHhBvx1ZUMopJPr2D\n" +
            "avTXCTSHY5JoX20KEwfu8QQXQRDUzyc0QKn9SiE3\n" +
    "-----END CERTIFICATE-----";
    @Test
    void testDirCertsSSLContext() throws Exception{
        Path certDirPath = Files.createTempDirectory("certs");
        File pemFile = new File(certDirPath.toAbsolutePath().toString(), "ca.pem");
        FileOutputStream fos = new FileOutputStream(pemFile);
        IOUtils.write(EXAMPLE_COM_PEM,fos);
        fos.close();
        SDKBuilder builder = SDKBuilder.newBuilder().sslFactoryFromDirectory(certDirPath.toAbsolutePath().toString());
        SSLFactory sslFactory = builder.getSslFactory();
        assertNotNull(sslFactory);
        X509Certificate[] acceptedIssuers=  sslFactory.getTrustManager().get().getAcceptedIssuers();
        assertEquals(1, Arrays.stream(acceptedIssuers).filter(x->x.getIssuerX500Principal().getName()
                .equals("CN=example.com")).count());
    }

    @Test
    void testKeystoreSSLContext() throws Exception{
        KeyStore keystore = KeyStoreUtils.createKeyStore();
        keystore.setCertificateEntry("example.com", PemUtils.parseCertificate(EXAMPLE_COM_PEM).get(0));
        Path keyStorePath = Files.createTempFile("ca", "jks");
        keystore.store(new FileOutputStream(keyStorePath.toAbsolutePath().toString()), "foo".toCharArray());
        SDKBuilder builder = SDKBuilder.newBuilder().sslFactoryFromKeyStore(keyStorePath.toAbsolutePath().toString(), "foo");
        SSLFactory sslFactory = builder.getSslFactory();
        assertNotNull(sslFactory);
        X509Certificate[] acceptedIssuers=  sslFactory.getTrustManager().get().getAcceptedIssuers();
        assertEquals(1, Arrays.stream(acceptedIssuers).filter(x->x.getIssuerX500Principal().getName()
                .equals("CN=example.com")).count());

    }


    @Test
    public void testPlatformPlainTextAndIDPWithSSL() throws Exception{
        sdkServicesSetup(false, true);
    }

    @Test
    void testSDKServicesWithTruststore() throws Exception{
        sdkServicesSetup(true, true);
    }

    @Test
    void testCreatingSDKServicesPlainText() throws Exception {
        sdkServicesSetup(false, false);
    }

    void sdkServicesSetup(boolean useSSLPlatform, boolean useSSLIDP) throws Exception{

        HeldCertificate rootCertificate = new HeldCertificate.Builder()
                .certificateAuthority(0)
                .build();
        String localhost = InetAddress.getByName("localhost").getCanonicalHostName();
        HeldCertificate serverCertificate = new HeldCertificate.Builder()
                .addSubjectAlternativeName(localhost)
                .commonName("CN=localhost")
                .signedBy(rootCertificate)
                .build();

        HandshakeCertificates serverHandshakeCertificates = new HandshakeCertificates.Builder()
                .heldCertificate(serverCertificate, rootCertificate.certificate())
                .build();

        Server platformServicesServer = null;
        Server kasServer = null;
        SDK.Services services = null;
        // we use the HTTP server for two things:
        // * it returns the OIDC configuration we use at bootstrapping time
        // * it fakes out being an IDP and returns an access token when need to retrieve an access token
        try (MockWebServer httpServer = new MockWebServer()) {
            if (useSSLIDP){
                httpServer.useHttps(serverHandshakeCertificates.sslSocketFactory(), false);
            }
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
            ServerBuilder<?> platformServicesServerBuilder = ServerBuilder
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
                    });
            if (useSSLPlatform){
                 platformServicesServerBuilder = platformServicesServerBuilder.useTransportSecurity(
                        new ByteArrayInputStream(serverCertificate.certificatePem().getBytes()),
                        new ByteArrayInputStream(serverCertificate.privateKeyPkcs8Pem().getBytes()));
            }

            platformServicesServer = platformServicesServerBuilder.build()
                    .start();

            ServerBuilder<?> kasServerBuilder = ServerBuilder
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
                    });

            if(useSSLPlatform){
                kasServerBuilder = kasServerBuilder.useTransportSecurity(
                        new ByteArrayInputStream(serverCertificate.certificatePem().getBytes()),
                        new ByteArrayInputStream(serverCertificate.privateKeyPkcs8Pem().getBytes()));
            }
            kasServer = kasServerBuilder.build()
                    .start();

            SDKBuilder servicesBuilder = SDKBuilder
                    .newBuilder()
                    .clientSecret("client-id", "client-secret")
                    .platformEndpoint("localhost:" + platformServicesServer.getPort());

            if(!useSSLPlatform) {
                servicesBuilder = servicesBuilder.useInsecurePlaintextConnection(true);
            }
            if (useSSLPlatform || useSSLIDP){
                servicesBuilder = servicesBuilder.sslFactory(SSLFactory.builder().withTrustMaterial(rootCertificate.
                        certificate()).build());
            }

            var servicesAndComponents = servicesBuilder.buildServices();
            if (useSSLPlatform || useSSLIDP) {
                assertThat(servicesAndComponents.trustManager).isNotNull();
            }
            assertThat(servicesAndComponents.interceptor).isNotNull();
            services = servicesAndComponents.services;

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

            int i =0; //some race condition with testing
            while(servicesDPoPHeader.get()==null && i < 10){
                Thread.sleep(10);
                i += 1;
            }
            assertThat(servicesDPoPHeader.get()).isNotNull();
            assertThat(servicesAuthHeader.get()).isEqualTo("DPoP hereisthetoken");

            var body = new String(accessTokenRequest.getBody().readByteArray(), StandardCharsets.UTF_8);
            assertThat(body).contains("grant_type=client_credentials");

            // now call KAS _on a different server_ and make sure that the interceptors provide us with auth tokens
            var keyAccess = new Manifest.KeyAccess();
            keyAccess.url = "localhost:" + kasServer.getPort();

            try {
                services.kas().unwrap(keyAccess, "");
            } catch (Exception ignoredException) {
                // not going to bother making a real request with real crypto, just make sure that
                // we have the right headers
            }
            i =0; //some race condition with testing
            while(kasDPoPHeader.get()==null && i < 10){
                Thread.sleep(10);
                i += 1;
            }
            assertThat(kasDPoPHeader.get()).isNotNull();
            assertThat(kasAuthHeader.get()).isEqualTo("DPoP hereisthetoken");
        } finally {
            if (platformServicesServer != null) {
                platformServicesServer.shutdownNow();
            }
            if (kasServer != null) {
                kasServer.shutdownNow();
            }
            if (services != null) {
                services.close();
            }
        }
    }

    /**
     * If auth is disabled then the `platform_issuer` isn't returned during bootstrapping. The SDK
     * should still function without auth if auth is disabled on the server
     * @throws IOException
     */
    @Test
    public void testSdkWithNoIssuerMakesRequests() throws IOException {
        WellKnownServiceGrpc.WellKnownServiceImplBase wellKnownService = new WellKnownServiceGrpc.WellKnownServiceImplBase() {
            @Override
            public void getWellKnownConfiguration(GetWellKnownConfigurationRequest request, StreamObserver<GetWellKnownConfigurationResponse> responseObserver) {
                // don't return a platform issuer
                responseObserver.onNext(GetWellKnownConfigurationResponse.getDefaultInstance());
                responseObserver.onCompleted();
            }
        };

        var authHeader = new AtomicReference<String>(null);
        var getNsCalled = new AtomicReference<Boolean>(false);

        var platformServices = ServerBuilder
                .forPort(getRandomPort())
                .directExecutor()
                .intercept(new ServerInterceptor() {
                    @Override
                    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                        authHeader.set(
                                headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER))
                        );
                        return next.startCall(call, headers);
                    }
                })
                .addService(wellKnownService)
                .addService(new NamespaceServiceGrpc.NamespaceServiceImplBase() {
                    @Override
                    public void getNamespace(GetNamespaceRequest request, StreamObserver<GetNamespaceResponse> responseObserver) {
                        getNsCalled.set(true);
                        responseObserver.onNext(GetNamespaceResponse.getDefaultInstance());
                        responseObserver.onCompleted();
                    }
                })
                .build();

        SDK sdk;
        try {
            platformServices.start();

            sdk = SDKBuilder.newBuilder()
                    .clientSecret("user", "password")
                    .platformEndpoint("localhost:" + platformServices.getPort())
                    .useInsecurePlaintextConnection(true)
                    .build();
            assertThat(sdk.getAuthInterceptor()).isEmpty();


            try {
                sdk.getServices().namespaces().getNamespace(GetNamespaceRequest.getDefaultInstance()).get();
            } catch (StatusRuntimeException ignored) {
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }

            assertThat(getNsCalled.get()).isTrue();
            assertThat(authHeader.get()).isNullOrEmpty();
        } finally {
            platformServices.shutdownNow();
        }
    }

    public static int getRandomPort() throws IOException {
        int randomPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            randomPort = socket.getLocalPort();
        }
        return randomPort;
    }
}
