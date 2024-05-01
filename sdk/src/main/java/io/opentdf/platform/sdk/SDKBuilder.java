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
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc;

import java.io.IOException;
import java.util.UUID;

/**
 * A builder class for creating instances of the SDK class.
 */
public class SDKBuilder {
    private static final String PLATFORM_ISSUER = "platform_issuer";
    private String platformEndpoint = null;
    private ClientAuthentication clientAuth = null;
    private Boolean usePlainText;

    public static SDKBuilder newBuilder() {
        SDKBuilder builder = new SDKBuilder();
        builder.usePlainText = false;

        return builder;
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

    // this is not exposed publicly so that it can be tested
    ManagedChannel buildChannel() {
        // we don't add the auth listener to this channel since it is only used to call the
        //    well known endpoint
        ManagedChannel bootstrapChannel = null;
        GetWellKnownConfigurationResponse config;
        try {
            bootstrapChannel = getManagedChannelBuilder().build();
            var stub = WellKnownServiceGrpc.newBlockingStub(bootstrapChannel);
            try {
                config = stub.getWellKnownConfiguration(GetWellKnownConfigurationRequest.getDefaultInstance());
            } catch (Exception e) {
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

        } catch (Exception e) {
            throw new SDKException("Error getting the issuer from the platform", e);
        }

        Issuer issuer = new Issuer(platformIssuer);
        OIDCProviderMetadata providerMetadata;
        try {
            providerMetadata = OIDCProviderMetadata.resolve(issuer);
        } catch (IOException | GeneralException e) {
            throw new SDKException("Error resolving the OIDC provider metadata", e);
        }

        RSAKey rsaKey;
        try {
            rsaKey = new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException e) {
            throw new SDKException("Error generating DPoP key", e);
        }

        GRPCAuthInterceptor interceptor = new GRPCAuthInterceptor(clientAuth, rsaKey, providerMetadata.getTokenEndpointURI());

        return getManagedChannelBuilder()
                .intercept(interceptor)
                .build();
    }

    public SDK build() {
        return new SDK(SDK.Services.newServices(buildChannel()));
    }

    private ManagedChannelBuilder<?> getManagedChannelBuilder() {
        ManagedChannelBuilder<?> channelBuilder = ManagedChannelBuilder
                .forTarget(platformEndpoint);

        if (usePlainText) {
            channelBuilder = channelBuilder.usePlaintext();
        }
        return channelBuilder;
    }
}
