package io.opentdf.platform.sdk;

import com.connectrpc.Interceptor;
import com.connectrpc.ProtocolClientConfig;
import com.connectrpc.ResponseMessageKt;
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
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.opentdf.platform.generated.kas.AccessServiceClient;
import io.opentdf.platform.generated.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.generated.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.generated.wellknownconfiguration.WellKnownServiceClient;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.pem.util.PemUtils;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * A builder class for creating instances of the SDK class.
 */
public class SDKBuilder {
    private static final String PLATFORM_ISSUER = "platform_issuer";
    private String platformEndpoint = null;
    private ClientAuthentication clientAuth = null;
    private Boolean usePlainText;
    private SSLFactory sslFactory;
    private AuthorizationGrant authzGrant;

    private static final Logger logger = LoggerFactory.getLogger(SDKBuilder.class);

    public static SDKBuilder newBuilder() {
        SDKBuilder builder = new SDKBuilder();
        builder.usePlainText = false;
        builder.clientAuth = null;
        builder.platformEndpoint = null;
        builder.authzGrant = null;

        return builder;
    }

    static String normalizeAddress(String urlString, boolean usePlaintext) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            url = tryParseHostAndPort(urlString);
        }
        final int port = url.getPort() == -1 ? ("http".equals(url.getProtocol()) ? 80 : 443) : url.getPort();
        final String protocol = usePlaintext && "http".equals(url.getProtocol()) ? "http" : "https";

        try {
            var returnUrl = new URL(protocol, url.getHost(), port, "").toString();
            logger.debug("normalized url [{}] to [{}]", urlString, returnUrl);
            return returnUrl;
        } catch (MalformedURLException e) {
            throw new SDKException("error creating KAS address", e);
        }
    }

    private static URL tryParseHostAndPort(String urlString) {
        URI uri;
        try {
            uri = new URI(null, urlString, null, null, null).parseServerAuthority();
        } catch (URISyntaxException e) {
            throw new SDKException("error trying to parse host and port", e);
        }

        try {
            return new URL(uri.getPort() == 443 ? "https" : "http", uri.getHost(), uri.getPort(), "");
        } catch (MalformedURLException e) {
            throw new SDKException("error trying to create URL from host and port", e);
        }
    }

    public SDKBuilder sslFactory(SSLFactory sslFactory) {
        this.sslFactory = sslFactory;
        return this;
    }

    /**
     * Add SSL Context with trusted certs from certDirPath
     * 
     * @param certsDirPath Path to a directory containing .pem or .crt trusted certs
     */
    public SDKBuilder sslFactoryFromDirectory(String certsDirPath) throws Exception {
        File certsDir = new File(certsDirPath);
        File[] certFiles = certsDir.listFiles((dir, name) -> name.endsWith(".pem") || name.endsWith(".crt"));
        logger.info("Loading certificates from: " + certsDir.getAbsolutePath());
        List<InputStream> certStreams = new ArrayList<>(certFiles.length);
        for (File certFile : certFiles) {
            certStreams.add(new FileInputStream(certFile));
        }
        X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(certStreams.toArray(new InputStream[0]));
        this.sslFactory = SSLFactory.builder().withDefaultTrustMaterial().withSystemTrustMaterial()
                .withTrustMaterial(trustManager).build();
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
        this.sslFactory = SSLFactory.builder().withDefaultTrustMaterial().withSystemTrustMaterial()
                .withTrustMaterial(Path.of(keystorePath),
                        keystorePassword == null ? "".toCharArray() : keystorePassword.toCharArray())
                .build();
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
        // the
        // well known endpoint
        ProtocolClient bootstrapClient = null;
        GetWellKnownConfigurationResponse config;
        bootstrapClient = getUnauthenticatedProtocolClient(platformEndpoint) ;
        var stub = new WellKnownServiceClient(bootstrapClient);
        try {
            config = ResponseMessageKt.getOrThrow(stub.getWellKnownConfigurationBlocking(GetWellKnownConfigurationRequest.getDefaultInstance(), Collections.emptyMap()).execute());
        } catch (StatusRuntimeException e) {
            Status status = Status.fromThrowable(e);
            throw new SDKException(String.format("Got grpc status [%s] when getting configuration", status), e);
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
                if (sslFactory != null) {
                    httpRequest.setSSLSocketFactory(sslFactory.getSslSocketFactory());
                }
            });
        } catch (IOException | GeneralException e) {
            throw new SDKException("Error resolving the OIDC provider metadata", e);
        }

        if (this.authzGrant == null) {
            this.authzGrant = new ClientCredentialsGrant();
        }
        var ts = new TokenSource(clientAuth, rsaKey, providerMetadata.getTokenEndpointURI(), this.authzGrant, sslFactory);
        return new AuthInterceptor(ts);
    }

    static class ServicesAndInternals {
        final Interceptor interceptor;
        final TrustManager trustManager;

        final SDK.Services services;

        ServicesAndInternals(Interceptor interceptor, TrustManager trustManager, SDK.Services services) {
            this.interceptor = interceptor;
            this.trustManager = trustManager;
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

        this.platformEndpoint = normalizeAddress(this.platformEndpoint, this.usePlainText);
        var authInterceptor = getAuthInterceptor(dpopKey);
        var kasClient = getKASClient(dpopKey, authInterceptor);
        var protocolClient = getUnauthenticatedProtocolClient(platformEndpoint, authInterceptor);

        return new ServicesAndInternals(
                authInterceptor,
                sslFactory == null ? null : sslFactory.getTrustManager().orElse(null),
                SDK.Services.newServices(protocolClient, kasClient));
    }

    @Nonnull
    private KASClient getKASClient(RSAKey dpopKey, Interceptor interceptor) {
        return new KASClient((String endpoint) -> new AccessServiceClient(getUnauthenticatedProtocolClient(endpoint, interceptor)), dpopKey, usePlainText);
    }

    public SDK build() {
        var services = buildServices();
        return new SDK(services.services, services.trustManager, services.interceptor);
    }

    private ProtocolClient getUnauthenticatedProtocolClient(String endpoint) {
        return getUnauthenticatedProtocolClient(endpoint, null);
    }

    private ProtocolClient getUnauthenticatedProtocolClient(String endpoint, Interceptor authInterceptor) {
        var httpClient = new OkHttpClient.Builder();
        if (usePlainText) {
            httpClient.protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
        }
        if (sslFactory != null) {
            if (sslFactory.getTrustManager().isEmpty()) {
                throw new SDKException("SSL factory must have a trust manager");
            }
            httpClient.sslSocketFactory(sslFactory.getSslSocketFactory(), sslFactory.getTrustManager().get());
        }
        var protocolClientConfig = new ProtocolClientConfig(
                endpoint,
                new GoogleJavaProtobufStrategy(),
                NetworkProtocol.GRPC,
                null,
                GETConfiguration.Enabled.INSTANCE,
                authInterceptor == null ? Collections.emptyList() : List.of((_config) -> authInterceptor)
        );

        return new ProtocolClient(new ConnectOkHttpClient(httpClient.build()), protocolClientConfig);
    }

    SSLFactory getSslFactory() {
        return this.sslFactory;
    }
}
