package io.opentdf.platform.sdk;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.SignedJWT;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc.AttributesServiceFutureStub;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc.NamespaceServiceFutureStub;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceGrpc.WellKnownServiceFutureStub;

public class SDK {

  protected OIDCProviderMetadata providerMetadata;
  private final ManagedChannel channel;
  public final AttributesServiceFutureStub attributes;
  public final NamespaceServiceFutureStub namespaces;
  public final SubjectMappingServiceFutureStub subjectMappings;
  public final ResourceMappingServiceFutureStub resourceMappings;
  private final WellKnownServiceFutureStub wellKnown;


  public SDK(SDKBuilder builder) throws JOSEException, IOException, GeneralException,
      InterruptedException, ExecutionException {

    RSAKey rsaKey = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString()).generate();

    ManagedChannelBuilder<?> channelBuilder =
        ManagedChannelBuilder.forTarget(builder.platformEndpoint)
            .intercept(new GRPCAuthInterceptor(builder.clientAuth, rsaKey));

    if (builder.usePlainText) {
      channelBuilder = channelBuilder.usePlaintext();
    }

    this.channel = channelBuilder.build();

    this.attributes = AttributesServiceGrpc.newFutureStub(channel);
    this.namespaces = NamespaceServiceGrpc.newFutureStub(channel);
    this.subjectMappings = SubjectMappingServiceGrpc.newFutureStub(channel);
    this.resourceMappings = ResourceMappingServiceGrpc.newFutureStub(channel);
    this.wellKnown = WellKnownServiceGrpc.newFutureStub(channel);

    GetWellKnownConfigurationResponse config = this.wellKnown.getWellKnownConfiguration(null).get();
    Issuer issuer =
        new Issuer(config.getConfiguration().getFieldsOrThrow("platform_issuer").getStringValue());

    this.providerMetadata = OIDCProviderMetadata.resolve(issuer);
  }

  public static class SDKBuilder {
    private String platformEndpoint;
    private ClientAuthentication clientAuth;
    private Boolean usePlainText;

    public SDKBuilder platformEndpoint(String platformEndpoint) {
      this.platformEndpoint = platformEndpoint;
      return this;
    }

    public SDKBuilder clientCredentialsBasic(String clientID, String clientSecret) {
      ClientID cid = new ClientID(clientID);
      Secret cs = new Secret(clientSecret);
      this.clientAuth = new ClientSecretBasic(cid, cs);
      return this;
    }

    public SDKBuilder usePlainText(Boolean usePlainText) {
      this.usePlainText = usePlainText;
      return this;
    }


    public SDK build() throws JOSEException, IOException, GeneralException, InterruptedException,
        ExecutionException {
      return new SDK(this);
    }


  }

  private class GRPCAuthInterceptor implements ClientInterceptor

  {

    private Instant tokenExpiryTime;
    private AccessToken token;
    private final ClientAuthentication clientAuth;
    private final RSAKey rsaKey;

    public GRPCAuthInterceptor(ClientAuthentication clientAuth, RSAKey rsaKey) {
      this.clientAuth = clientAuth;
      this.rsaKey = rsaKey;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method,
        CallOptions callOptions, Channel next) {
      return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
        @Override
        public void start(Listener<RespT> responseListener, Metadata headers) {
          if (method.getFullMethodName()
              .equals("wellknownconfiguration.WellKnownService/GetWellKnownConfiguration")) {
            super.start(responseListener, headers);
            return;
          }
          AccessToken t = getToken();
          System.out.println("Access token: " + t.getValue());
          System.out.println("Lifetime: " + t.getLifetime());
          System.out.println("Expires: " + t.toJSONObject().get("expires_in"));
          headers.put(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
              "Bearer " + t.getValue());

          super.start(responseListener, headers);
        }
      };
    }

    private AccessToken getToken() {
      try {

        // If the token is expired or initially null, get a new token
        if (isTokenExpired() | this.token == null) {
          System.out.println("getting new access token");

          // Construct the client credentials grant
          AuthorizationGrant clientGrant = new ClientCredentialsGrant();

          // Make the token request
          TokenRequest tokenRequest = new TokenRequest(providerMetadata.getTokenEndpointURI(),
              clientAuth, clientGrant, null);
          HTTPRequest httpRequest = tokenRequest.toHTTPRequest();

          DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(rsaKey, JWSAlgorithm.RS256);

          SignedJWT proof =
              dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI());

          httpRequest.setDPoP(proof);
          System.out.println("DPoP: " + proof.serialize());
          TokenResponse tokenResponse;

          HTTPResponse httpResponse = httpRequest.send();

          tokenResponse = TokenResponse.parse(httpResponse);
          if (!tokenResponse.indicatesSuccess()) {
            ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
            System.out.println("Token response: " + error.getHTTPStatusCode());
            throw new RuntimeException("Token request failed: " + error);
          }

          this.token = tokenResponse.toSuccessResponse().getTokens().getAccessToken();
          // DPoPAccessToken dPoPAccessToken = tokens.getDPoPAccessToken();



          if (token.getLifetime() != 0) {
            this.tokenExpiryTime = Instant.now().plusSeconds(token.getLifetime() / 3);
          }

        } else {
          // If the token is still valid or not initially null, return the cached token
          System.out.println("using cached token");
          return this.token;
        }

      } catch (Exception e) {
        // TODO Auto-generated catch block
        throw new RuntimeException("Failed to get token", e);
      }
      return this.token;
    }

    private boolean isTokenExpired() {
      return this.tokenExpiryTime != null && this.tokenExpiryTime.isBefore(Instant.now());
    }
  }

}

