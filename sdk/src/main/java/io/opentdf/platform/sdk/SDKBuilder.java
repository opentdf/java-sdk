package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.connectrpc.Interceptor;
import com.connectrpc.ProtocolClientConfig;
import com.connectrpc.extensions.GoogleJavaProtobufStrategy;
import com.connectrpc.impl.ProtocolClient;
import com.connectrpc.okhttp.ConnectOkHttpClient;
import com.connectrpc.protocols.GETConfiguration;
import com.connectrpc.protocols.NetworkProtocol;
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
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.pem.util.PemUtils;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.BiFunction;

/**
 * A builder class for creating instances of the SDK class.
 */
public class SDKBuilder {
    private static final String PLATFORM_ISSUER = "platform_issuer";
    private String platformEndpoint = null;
    private ClientAuthentication clientAuth = null;
    private ChannelConfig channelConfig = new ChannelConfig();
    private AuthorizationGrant authzGrant;

    private static final Logger logger = LoggerFactory.getLogger(SDKBuilder.class);

    public static SDKBuilder newBuilder() {
        SDKBuilder builder = new SDKBuilder();
        builder.clientAuth = null;
        builder.platformEndpoint = null;
        builder.authzGrant = null;

        return builder;
    }

    /**
     * Add an SSLFactory to the SDKBuilder. The SDK will use this factory to create
     * and validate SSL connections
     *
     * @param sslFactory SSL factory to use
     * @deprecated Use methods on {@link ChannelConfig} instead and then call {@link SDKBuilder#channelConfig}
     */
    public SDKBuilder sslFactory(SSLFactory sslFactory) {
        this.channelConfig.sslFactory(sslFactory);
        return this;
    }

    /**
     * Add SSL Context with trusted certs from certDirPath
     *
     * @param certsDirPath Path to a directory containing .pem or .crt trusted certs
     * @deprecated Use methods on {@link ChannelConfig} instead and then call {@link SDKBuilder#channelConfig}
     */
    @Deprecated
    public SDKBuilder sslFactoryFromDirectory(String certsDirPath) throws Exception {
        this.channelConfig.sslFactoryFromDirectory(certsDirPath);
        return this;
    }

    /**
     * Add SSL Context with default system trust material + certs contained in a
     * Java keystore
     * 
     * @param keystorePath     Path to keystore
     * @param keystorePassword Password to keystore
     * @deprecated Use methods on {@link ChannelConfig} instead and then call {@link SDKBuilder#channelConfig}
     */
    @Deprecated
    public SDKBuilder sslFactoryFromKeyStore(String keystorePath, String keystorePassword) {
        this.channelConfig.sslFactoryFromKeyStore(keystorePath, keystorePassword);
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

    public SDKBuilder channelConfig(ChannelConfig channelConfig) {
        this.channelConfig = channelConfig;
        return this;
    }

    public static class ChannelConfig {
        public ChannelConfig useInsecurePlaintextConnection(boolean plaintext) {
            this.usePlaintext = plaintext;
            return this;
        }

        public ChannelConfig sslFactory(SSLFactory sslFactory) {
            this.sslFactory = sslFactory;
            return this;
        }

        public ChannelConfig sslFactoryFromDirectory(String certsDirPath) throws Exception {
            File certsDir = new File(certsDirPath);
            File[] certFiles = certsDir.listFiles((dir, name) -> name.endsWith(".pem") || name.endsWith(".crt"));
            logger.info("Loading certificates from: " + certsDir.getAbsolutePath());
            List<InputStream> certStreams = new ArrayList<>(certFiles.length);
            for (File certFile : certFiles) {
                certStreams.add(new FileInputStream(certFile));
            }
            X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certStreams.toArray(new InputStream[0]));
            var sslFactory1 = SSLFactory.builder().withDefaultTrustMaterial().withSystemTrustMaterial()
                    .withTrustMaterial(trustManager).build();
            this.sslFactory = sslFactory1;
            return this;
        }

        public ChannelConfig sslFactoryFromKeyStore(String keystorePath, String keystorePassword) {
            this.sslFactory = SSLFactory.builder().withDefaultTrustMaterial().withSystemTrustMaterial()
                    .withTrustMaterial(Path.of(keystorePath),
                            keystorePassword == null ? "".toCharArray() : keystorePassword.toCharArray())
                    .build();
            return this;
        }

        private boolean usePlaintext = false;
        private SSLFactory sslFactory = null;
    }

    /**
     * If set to `true` `http` connections to platform services are allowed. In particular,
     * use this option to unwrap TDFs using KASs that are not using TLS. Also, if KASs use
     * <hostname>:<port> addresses then this option must be set in order for the SDK to
     * call the KAS without TLS.
     * @param usePlainText
     * @deprecated use method on {@link ChannelConfig} instead
     */
    public SDKBuilder useInsecurePlaintextConnection(Boolean usePlainText) {
        this.channelConfig.useInsecurePlaintextConnection(usePlainText);
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
        var httpClient = getHttpClient(channelConfig);
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
                if (channelConfig.sslFactory != null) {
                    httpRequest.setSSLSocketFactory(channelConfig.sslFactory.getSslSocketFactory());
                }
            });
        } catch (IOException | GeneralException e) {
            throw new SDKException("Error resolving the OIDC provider metadata", e);
        }

        if (this.authzGrant == null) {
            this.authzGrant = new ClientCredentialsGrant();
        }
        var ts = new TokenSource(clientAuth, rsaKey, providerMetadata.getTokenEndpointURI(), this.authzGrant, channelConfig.sslFactory);
        return new AuthInterceptor(ts);
    }

    static class ServicesAndInternals {
        final Interceptor interceptor;
        final TrustManager trustManager;
        final ProtocolClient protocolClient;

        final SDK.Services services;

        ServicesAndInternals(Interceptor interceptor, TrustManager trustManager, ProtocolClient protocolClient, SDK.Services services) {
            this.interceptor = interceptor;
            this.trustManager = trustManager;
            this.protocolClient = protocolClient;
            this.services = services;
        }
    }

    ServicesAndInternals buildServices() {
        RSAKey dpopKey;
        try {
            dpopKey = new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException e) {
            throw new SDKException("Error generating DPoP key", e);
        }

        this.platformEndpoint = AddressNormalizer.normalizeAddress(this.platformEndpoint, this.channelConfig.usePlaintext);
        var authInterceptor = getAuthInterceptor(dpopKey);
        var kasClient = getKASClient(dpopKey, authInterceptor);
        var httpClient = getHttpClient(channelConfig);
        var client = getProtocolClient(platformEndpoint, httpClient, authInterceptor);
        var attributeService = new AttributesServiceClient(client);
        var namespaceService = new NamespaceServiceClient(client);
        var subjectMappingService = new SubjectMappingServiceClient(client);
        var resourceMappingService = new ResourceMappingServiceClient(client);
        var authorizationService = new AuthorizationServiceClient(client);
        var kasRegistryService = new KeyAccessServerRegistryServiceClient(client);

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
            public KeyAccessServerRegistryServiceClient kasRegistry() {
                return kasRegistryService;
            }

            @Override
            public SDK.KAS kas() {
                return kasClient;
            }
        };

        return new ServicesAndInternals(
                authInterceptor,
                channelConfig.sslFactory == null ? null : channelConfig.sslFactory.getTrustManager().orElse(null),
                client,
                services);
    }

    @Nonnull
    private KASClient getKASClient(RSAKey dpopKey, Interceptor interceptor) {
        BiFunction<OkHttpClient, String, ProtocolClient> protocolClientFactory = (OkHttpClient client, String address) -> getProtocolClient(address, client, interceptor);
        return new KASClient(getHttpClient(channelConfig), protocolClientFactory, dpopKey, channelConfig.usePlaintext);
    }

    public SDK build() {
        var services = buildServices();
        return new SDK(services.services, services.trustManager, services.interceptor, services.protocolClient, platformEndpoint);
    }

    private static ProtocolClient getUnauthenticatedProtocolClient(String endpoint, OkHttpClient httpClient) {
        return getProtocolClient(endpoint, httpClient, null);
    }

    /**
     * Creates a new protocol client for the given endpoint and HTTP client.
     * @param endpoint
     * @param httpClient
     * @param authInterceptor
     * @return
     */
    public static ProtocolClient getProtocolClient(@Nonnull String endpoint, @Nonnull OkHttpClient httpClient, @Nullable Interceptor authInterceptor) {
        var protocolClientConfig = new ProtocolClientConfig(
                Objects.requireNonNull(endpoint),
                new GoogleJavaProtobufStrategy(),
                NetworkProtocol.GRPC,
                null,
                GETConfiguration.Enabled.INSTANCE,
                authInterceptor == null ? Collections.emptyList() : List.of(ignoredConfig -> authInterceptor)
        );

        return new ProtocolClient(new ConnectOkHttpClient(Objects.requireNonNull(httpClient)), protocolClientConfig);
    }

    /**
     * Creates a new HTTP client for the given channel configuration.
     * @param channelConfig
     * @return
     */
    public static OkHttpClient getHttpClient(ChannelConfig channelConfig) {
        // using a single http client is apparently the best practice, subject to everyone wanting to
        // have the same protocols
        var httpClient = new OkHttpClient.Builder();
        if (channelConfig.usePlaintext) {
            // we can only connect using HTTP/2 without any negotiation when using plain test
            httpClient.protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
        }
        if (channelConfig.sslFactory != null) {
            var trustManager = channelConfig.sslFactory.getTrustManager();
            if (trustManager.isEmpty()) {
                throw new SDKException("SSL factory must have a trust manager");
            }
            httpClient.sslSocketFactory(channelConfig.sslFactory.getSslSocketFactory(), trustManager.get());
        }
        return httpClient.build();
    }

    SSLFactory getSslFactoryFromCertDirectory() {
        return this.channelConfig.sslFactory;
    }
}
