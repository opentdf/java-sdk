package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.grpc.*;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.pem.util.PemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
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

    private static final Logger logger = LoggerFactory.getLogger(SDKBuilder.class);

    public static SDKBuilder newBuilder() {
        SDKBuilder builder = new SDKBuilder();
        builder.usePlainText = false;
        builder.clientAuth = null;
        builder.platformEndpoint = null;

        return builder;
    }

    public SDKBuilder sslFactory(SSLFactory sslFactory) {
        this.sslFactory = sslFactory;
        return this;
    }

    /**
     * Add SSL Context with trusted certs from certDirPath
     * @param certsDirPath Path to a directory containing .pem or .crt trusted certs
     * @return
     */
    public SDKBuilder sslFactoryFromDirectory(String certsDirPath)  throws Exception{
        File certsDir = new File(certsDirPath);
        File[] certFiles =
                certsDir.listFiles((dir, name) -> name.endsWith(".pem") || name.endsWith(".crt"));
        logger.info("Loading certificates from: " + certsDir.getAbsolutePath());
        List<InputStream> certStreams = new ArrayList<>();
        for (File certFile : certFiles) {
            certStreams.add(new FileInputStream(certFile));
        }
        X509ExtendedTrustManager trustManager =
                PemUtils.loadTrustMaterial(certStreams.toArray(new InputStream[0]));
        this.sslFactory =
                SSLFactory.builder().withDefaultTrustMaterial().withSystemTrustMaterial()
                        .withTrustMaterial(trustManager).build();
        return this;
    }

    /**
     * Add SSL Context with default system trust material + certs contained in a Java keystore
     * @param keystorePath Path to keystore
     * @param keystorePassword Password to keystore
     * @return
     */
    public SDKBuilder sslFactoryFromKeyStore(String keystorePath, String keystorePassword) {
        this.sslFactory =
                SSLFactory.builder().withDefaultTrustMaterial().withSystemTrustMaterial()
                        .withTrustMaterial(Path.of(keystorePath), keystorePassword==null ?
                                "".toCharArray() : keystorePassword.toCharArray()).build();
        return this;
    }

    public SDKBuilder platformEndpoint(String platformEndpoint) {
        this.platformEndpoint = platformEndpoint;
        return this;
    }

    public SDKBuilder clientSecret(String clientID, String clientSecret) {
        ClientID cid = new ClientID(clientID);
        Secret cs = new Secret(clientSecret);
        this.clientAuth = new ClientSecretBasic(cid, cs);
        return this;
    }

    public SDKBuilder useInsecurePlaintextConnection(Boolean usePlainText) {
        this.usePlainText = usePlainText;
        return this;
    }

    private GRPCAuthInterceptor getGrpcAuthInterceptor(RSAKey rsaKey) {
        if (platformEndpoint == null) {
            throw new SDKException("cannot build an SDK without specifying the platform endpoint");
        }

        if (clientAuth == null) {
            // this simplifies things for now, if we need to support this case we can revisit
            throw new SDKException("cannot build an SDK without specifying OAuth credentials");
        }

        // we don't add the auth listener to this channel since it is only used to call the
        //    well known endpoint
        ManagedChannel bootstrapChannel = null;
        GetWellKnownConfigurationResponse config;
        try {
            bootstrapChannel = getManagedChannelBuilder(platformEndpoint).build();
            var stub = WellKnownServiceGrpc.newBlockingStub(bootstrapChannel);
            try {
                config = stub.getWellKnownConfiguration(GetWellKnownConfigurationRequest.getDefaultInstance());
            } catch (StatusRuntimeException e) {
                Status status = Status.fromThrowable(e);
                throw new SDKException(String.format("Got grpc status [%s] when getting configuration", status), e);
            }
        } finally {
            if (bootstrapChannel != null) {
                bootstrapChannel.shutdown();
            }
        }

        String platformIssuer;
        try {
            platformIssuer = config
                    .getConfiguration()
                    .getFieldsOrThrow(PLATFORM_ISSUER)
                    .getStringValue();

        } catch (StatusRuntimeException e) {
            throw new SDKException("Error getting the issuer from the platform", e);
        }

        Issuer issuer = new Issuer(platformIssuer);
        OIDCProviderMetadata providerMetadata;
        try {
            providerMetadata = OIDCProviderMetadata.resolve(issuer, httpRequest -> {
                if (sslFactory!=null) {
                    httpRequest.setSSLSocketFactory(sslFactory.getSslSocketFactory());
                }
            });
        } catch (IOException | GeneralException e) {
            throw new SDKException("Error resolving the OIDC provider metadata", e);
        }

        return new GRPCAuthInterceptor(clientAuth, rsaKey, providerMetadata.getTokenEndpointURI(), sslFactory);
    }

    SDK.Services buildServices() {
        RSAKey dpopKey;
        try {
            dpopKey = new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException e) {
            throw new SDKException("Error generating DPoP key", e);
        }

        var authInterceptor = getGrpcAuthInterceptor(dpopKey);
        var channel = getManagedChannelBuilder(platformEndpoint).intercept(authInterceptor).build();
        var client = new KASClient(endpoint -> getManagedChannelBuilder(endpoint).intercept(authInterceptor).build(), dpopKey);
        return SDK.Services.newServices(channel, client);
    }

    public SDK build() {
        return new SDK(buildServices());
    }

    /**
     * This produces a channel configured with all the available SDK options. The only
     * reason it can't take in an interceptor is because we need to create a channel that
     * doesn't have any authentication when we are bootstrapping
     * @param endpoint The endpoint that we are creating the channel for
     * @return {@type ManagedChannelBuilder<?>} configured with the SDK options
     */
    private ManagedChannelBuilder<?> getManagedChannelBuilder(String endpoint) {
        ManagedChannelBuilder<?> channelBuilder;
        if (sslFactory != null) {
            channelBuilder = Grpc.newChannelBuilder(endpoint, TlsChannelCredentials.newBuilder()
                    .trustManager(sslFactory.getTrustManager().get()).build());
        }else{
            channelBuilder = ManagedChannelBuilder.forTarget(endpoint);
        }

        if (usePlainText) {
            channelBuilder = channelBuilder.usePlaintext();
        }
        return channelBuilder;
    }

    SSLFactory getSslFactory(){
        return this.sslFactory;
    }
}
