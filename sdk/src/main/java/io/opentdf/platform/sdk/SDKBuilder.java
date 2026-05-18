package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.connectrpc.Interceptor;
import com.connectrpc.ProtocolClientConfig;
import com.connectrpc.extensions.GoogleJavaProtobufStrategy;
import com.connectrpc.impl.ProtocolClient;
import com.connectrpc.okhttp.ConnectOkHttpClient;
import com.connectrpc.protocols.GETConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.opentdf.platform.authorization.AuthorizationServiceClient;
import io.opentdf.platform.policy.attributes.AttributesServiceClient;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClient;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClient;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClient;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClient;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;

/**
 * A builder class for creating instances of the SDK class.
 */
public class SDKBuilder {
    private static final String PLATFORM_ISSUER = "platform_issuer";
    private String platformEndpoint = null;
    private ClientAuthentication clientAuth = null;
    private Boolean usePlainText;
    private SSLSocketFactory sslSocketFactory;
    private X509TrustManager trustManager;
    private AuthorizationGrant authzGrant;
    private ProtocolType protocolType = ProtocolType.CONNECT;
    private SrtSigner srtSigner;

    private static final Logger logger = LoggerFactory.getLogger(SDKBuilder.class);

    public static SDKBuilder newBuilder() {
        SDKBuilder builder = new SDKBuilder();
        builder.usePlainText = false;
        builder.clientAuth = null;
        builder.platformEndpoint = null;
        builder.authzGrant = null;

        return builder;
    }

    /**
     * The SDK will trust the certs that this TrustManager trusts
     * @param trustManager
     */
    public SDKBuilder sslFactoryFromTrustManager(X509TrustManager trustManager) {
        TrustProvider trustProvider;
        try {
            trustProvider = TrustProvider.fromTrustManager(trustManager);
        } catch (GeneralSecurityException e) {
            throw new SDKException("error creating trust provider", e);
        }
        this.trustManager = trustManager;
        this.sslSocketFactory = trustProvider.getSslSocketFactory();
        return this;
    }

    /**
     * Configure the SDK to use the supplied {@link SSLSocketFactory} together with a matching
     * {@link X509TrustManager}. The trust manager is used by OkHttp for certificate pinning and
     * cleartext-fallback decisions; supply this overload when the caller has a trust manager that
     * matches the socket factory's trust material (e.g. both built from a {@link TrustProvider}).
     */
    public SDKBuilder sslFactory(SSLSocketFactory sslSocketFactory, X509TrustManager trustManager) {
        this.sslSocketFactory = sslSocketFactory;
        this.trustManager = trustManager;
        return this;
    }

    /**
     * Configure the SDK to use the supplied {@link SSLSocketFactory}. {@link SDKBuilder#sslFactory(SSLSocketFactory, X509TrustManager)}
     * should be preferred since OkHttp will use reflection to derive a TrustManager which may
     * fail on some platforms because of stronger forms of encapsulation.
     */
    public SDKBuilder sslFactory(SSLSocketFactory sslSocketFactory) {
        this.sslSocketFactory = sslSocketFactory;
        this.trustManager = null;
        return this;
    }

    /**
     * Add SSL Context with trusted certs from certDirPath
     *
     * @param certsDirPath Path to a directory containing .pem or .crt trusted certs
     */
    public SDKBuilder sslFactoryFromDirectory(String certsDirPath) throws Exception {
        logger.info("Loading certificates from: {}", certsDirPath);
        TrustProvider provider = TrustProvider.fromDirectory(certsDirPath);
        this.sslSocketFactory = provider.getSslSocketFactory();
        this.trustManager = provider.getTrustManager();
        return this;
    }

    /**
     * Add SSL Context with default system trust material + certs contained in a
     * Java keystore
     *
     * @param keystorePath     Path to keystore
     * @param keystorePassword Password to keystore
     */
    public SDKBuilder sslFactoryFromKeyStore(String keystorePath, String keystorePassword) {
        try {
            TrustProvider provider = TrustProvider.fromKeyStore(
                    Path.of(keystorePath),
                    keystorePassword == null ? null : keystorePassword.toCharArray());
            this.sslSocketFactory = provider.getSslSocketFactory();
            this.trustManager = provider.getTrustManager();
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new SDKException("failed to load keystore from " + keystorePath, e);
        }
        return this;
    }

    public SDKBuilder platformEndpoint(String platformEndpoint) {
        this.platformEndpoint = platformEndpoint;
        return this;
    }

    public SDKBuilder authorizationGrant(AuthorizationGrant authzGrant) {
        if (this.authzGrant != null) {
            throw new RuntimeException("Authorization grant can't be specified twice");
        }
        this.authzGrant = authzGrant;
        return this;
    }

    public SDKBuilder tokenExchange(String jwt) {
        if (this.authzGrant != null) {
            throw new RuntimeException("Authorization grant can't be specified twice");
        }

        BearerAccessToken token = new BearerAccessToken(jwt);
        this.authzGrant = new TokenExchangeGrant(token, TokenTypeURI.ACCESS_TOKEN);
        return this;
    }

    public SDKBuilder clientSecret(String clientID, String clientSecret) {
        ClientID cid = new ClientID(clientID);
        Secret cs = new Secret(clientSecret);
        this.clientAuth = new ClientSecretBasic(cid, cs);
        return this;
    }

    /**
     * If set to `true` `http` connections to platform services are allowed. In particular,
     * use this option to unwrap TDFs using KASs that are not using TLS. Also, if KASs use
     * <hostname>:<port> addresses then this option must be set in order for the SDK to
     * call the KAS without TLS.
     * @param usePlainText
     * @return
     */
    public SDKBuilder useInsecurePlaintextConnection(Boolean usePlainText) {
        this.usePlainText = usePlainText;
        return this;
    }

    /**
     * Set the network protocol to use for communication with platform services.
     * 
     * @param protocolType the protocol type to use (CONNECT, GRPC, or GRPC_WEB)
     * @return this builder instance for method chaining
     * @throws IllegalArgumentException if protocolType is null
     * @see ProtocolType for available protocol options
     */
    public SDKBuilder protocol(ProtocolType protocolType) {
        if (protocolType == null) {
            throw new IllegalArgumentException("ProtocolType cannot be null");
        }
        this.protocolType = protocolType;
        return this;
    }

    public SDKBuilder srtSigner(SrtSigner signer) {
        this.srtSigner = signer;
        return this;
    }

    private Interceptor getAuthInterceptor(RSAKey rsaKey) {
        if (platformEndpoint == null) {
            throw new SDKException("cannot build an SDK without specifying the platform endpoint");
        }

        if (clientAuth == null) {
            // this simplifies things for now, if we need to support this case we can
            // revisit
            throw new SDKException("cannot build an SDK without specifying OAuth credentials");
        }

        // we don't add the auth listener to this channel since it is only used to call
        // the well known endpoint
        GetWellKnownConfigurationResponse config;
        var httpClient = getHttpClient();
        ProtocolClient bootstrapClient = getUnauthenticatedProtocolClient(platformEndpoint, httpClient) ;
        var stub = new WellKnownServiceClient(bootstrapClient);
        try {
            config = RequestHelper.getOrThrow(stub.getWellKnownConfigurationBlocking(GetWellKnownConfigurationRequest.getDefaultInstance(), Collections.emptyMap()).execute());
        } catch (ConnectException e) {
            throw new SDKException(String.format("Got grpc status [%s] when getting configuration", e.getCode()), e);
        }

        String platformIssuer;
        try {
            platformIssuer = config
                    .getConfiguration()
                    .getFieldsOrThrow(PLATFORM_ISSUER)
                    .getStringValue();
        } catch (IllegalArgumentException e) {
            logger.warn(
                    "no `platform_issuer` found in well known configuration. requests from the SDK will be unauthenticated",
                    e);
            return null;
        }

        Issuer issuer = new Issuer(platformIssuer);
        OIDCProviderMetadata providerMetadata;
        try {
            providerMetadata = OIDCProviderMetadata.resolve(issuer, httpRequest -> {
                if (sslSocketFactory != null) {
                    httpRequest.setSSLSocketFactory(sslSocketFactory);
                }
            });
        } catch (IOException | GeneralException e) {
            throw new SDKException("Error resolving the OIDC provider metadata", e);
        }

        if (this.authzGrant == null) {
            this.authzGrant = new ClientCredentialsGrant();
        }
        var ts = new TokenSource(clientAuth, rsaKey, providerMetadata.getTokenEndpointURI(), this.authzGrant, sslSocketFactory);
        return new AuthInterceptor(ts);
    }

    static class ServicesAndInternals {
        final Interceptor interceptor;
        final TrustManager trustManager;
        final ProtocolClient protocolClient;
        final SrtSigner srtSigner;

        final SDK.Services services;

        ServicesAndInternals(Interceptor interceptor, TrustManager trustManager, SDK.Services services, ProtocolClient protocolClient, SrtSigner srtSigner) {
            this.interceptor = interceptor;
            this.trustManager = trustManager;
            this.services = services;
            this.protocolClient = protocolClient;
            this.srtSigner = srtSigner;
        }
    }

    ServicesAndInternals buildServices() {
        // Validate configuration compatibility
        if (Boolean.TRUE.equals(usePlainText) && protocolType == ProtocolType.GRPC_WEB) {
            throw new SDKException("gRPC-Web protocol is not compatible with useInsecurePlaintextConnection(true). " +
                    "gRPC-Web is designed for web browsers and typically operates over HTTP/1.1, " +
                    "while plaintext connections force HTTP/2 prior knowledge.");
        }
        
        RSAKey dpopKey;
        try {
            dpopKey = new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException e) {
            throw new SDKException("Error generating DPoP key", e);
        }

        this.platformEndpoint = AddressNormalizer.normalizeAddress(this.platformEndpoint, this.usePlainText);
        var authInterceptor = getAuthInterceptor(dpopKey);
        var srtSignerToUse = this.srtSigner == null ? new DefaultSrtSigner(dpopKey) : this.srtSigner;
        var kasClient = getKASClient(srtSignerToUse, authInterceptor);
        var httpClient = getHttpClient();
        var client = getProtocolClient(platformEndpoint, httpClient, authInterceptor);
        var attributeService = new AttributesServiceClient(client);
        var namespaceService = new NamespaceServiceClient(client);
        var subjectMappingService = new SubjectMappingServiceClient(client);
        var resourceMappingService = new ResourceMappingServiceClient(client);
        var authorizationService = new AuthorizationServiceClient(client);
        var authorizationServiceV2 = new io.opentdf.platform.authorization.v2.AuthorizationServiceClient(client);
        var kasRegistryService = new KeyAccessServerRegistryServiceClient(client);
        var wellKnownService = new WellKnownServiceClient(client);

        var services = new SDK.Services() {
            @Override
            public void close() {
                kasClient.close();
                httpClient.dispatcher().executorService().shutdown();
                httpClient.connectionPool().evictAll();
            }

            @Override
            public AttributesServiceClient attributes() {
                return attributeService;
            }

            @Override
            public NamespaceServiceClient namespaces() {
                return namespaceService;
            }

            @Override
            public SubjectMappingServiceClient subjectMappings() {
                return subjectMappingService;
            }

            @Override
            public ResourceMappingServiceClient resourceMappings() {
                return resourceMappingService;
            }

            @Override
            public AuthorizationServiceClient authorization() {
                return authorizationService;
            }

            @Override
            public io.opentdf.platform.authorization.v2.AuthorizationServiceClient authorizationV2() {
                return authorizationServiceV2;
            }

            @Override
            public KeyAccessServerRegistryServiceClient kasRegistry() {
                return kasRegistryService;
            }

            @Override
            public WellKnownServiceClientInterface wellknown() {
                return wellKnownService;
            }

            @Override
            public SDK.KAS kas() {
                return kasClient;
            }
        };

        return new ServicesAndInternals(
                authInterceptor,
                trustManager,
                services,
                client,
                srtSignerToUse);
    }

    @Nonnull
    private KASClient getKASClient(SrtSigner srtSigner, Interceptor interceptor) {
        BiFunction<OkHttpClient, String, ProtocolClient> protocolClientFactory = (OkHttpClient client, String address) -> getProtocolClient(address, client, interceptor);
        return new KASClient(getHttpClient(), protocolClientFactory, srtSigner, usePlainText);
    }

    public SDK build() {
        var services = buildServices();
        return new SDK(services.services, services.trustManager, services.interceptor, services.protocolClient, platformEndpoint, services.srtSigner);
    }

    private ProtocolClient getUnauthenticatedProtocolClient(String endpoint, OkHttpClient httpClient) {
        return getProtocolClient(endpoint, httpClient, null);
    }

    private ProtocolClient getProtocolClient(String endpoint, OkHttpClient httpClient, Interceptor authInterceptor) {
        var protocolClientConfig = new ProtocolClientConfig(
                endpoint,
                new GoogleJavaProtobufStrategy(),
                protocolType.getNetworkProtocol(),
                null,
                GETConfiguration.Enabled.INSTANCE,
                authInterceptor == null ? Collections.emptyList() : List.of(ignoredConfig -> authInterceptor)
        );

        return new ProtocolClient(new ConnectOkHttpClient(httpClient), protocolClientConfig);
    }

    @SuppressWarnings("deprecation")
    private OkHttpClient getHttpClient() {
        // using a single http client is apparently the best practice, subject to everyone wanting to
        // have the same protocols
        var httpClient = new OkHttpClient.Builder();
        if (usePlainText) {
            // For plaintext connections, we need HTTP/2 prior knowledge because gRPC servers
            // expect HTTP/2, and Connect protocol can communicate with gRPC servers over HTTP/2
            httpClient.protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
        }
        if (sslSocketFactory != null) {
            if (trustManager != null) {
                httpClient.sslSocketFactory(sslSocketFactory, trustManager);
            } else {
                // Caller supplied an SSLSocketFactory without a matching trust manager (e.g. via
                // sslFactory(SSLSocketFactory)). Falls back to OkHttp's reflection-based platform
                // default trust manager — only the SSLSocketFactory governs the actual handshake.
                httpClient.sslSocketFactory(sslSocketFactory);
            }
        }
        return httpClient.build();
    }

    SSLSocketFactory getSslFactory() {
        return this.sslSocketFactory;
    }

    X509TrustManager getTrustManager() {
        return this.trustManager;
    }
}
