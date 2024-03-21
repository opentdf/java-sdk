package io.opentdf.platform.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import javax.management.RuntimeErrorException;
import org.checkerframework.checker.units.qual.m;
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

/**
 * The SDK class represents a software development kit for interacting with the opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf platform.
 */
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

  /**
   * A builder class for creating instances of the SDK class.
   */
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


  /**
   * The GRPCAuthInterceptor class is responsible for intercepting client calls before they are sent
   * to the server. It adds authentication headers to the requests by fetching and caching access
   * tokens.
   */
  private class GRPCAuthInterceptor implements ClientInterceptor

  {

    private Instant tokenExpiryTime;
    private AccessToken token;
    private final ClientAuthentication clientAuth;
    private final RSAKey rsaKey;

    /**
     * Constructs a new GRPCAuthInterceptor with the specified client authentication and RSA key.
     *
     * @param clientAuth the client authentication to be used by the interceptor
     * @param rsaKey the RSA key to be used by the interceptor
     */
    public GRPCAuthInterceptor(ClientAuthentication clientAuth, RSAKey rsaKey) {
      this.clientAuth = clientAuth;
      this.rsaKey = rsaKey;
    }

    /**
     * Intercepts the client call before it is sent to the server.
     *
     * @param method The method descriptor for the call.
     * @param callOptions The call options for the call.
     * @param next The next channel in the channel pipeline.
     * @param <ReqT> The type of the request message.
     * @param <RespT> The type of the response message.
     * @return A client call with the intercepted behavior.
     */
    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method,
        CallOptions callOptions, Channel next) {
      return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
        @Override
        public void start(Listener<RespT> responseListener, Metadata headers) {
          // Not sure the best way to handle this but we need to ignore auth here for wellknown on
          // the initial sdk setup
          if (method.getFullMethodName()
              .equals("wellknownconfiguration.WellKnownService/GetWellKnownConfiguration")) {
            super.start(responseListener, headers);
            return;
          }
          // Get the access token
          AccessToken t = getToken();

          headers.put(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
              "DPoP " + t.getValue());

          // Build the DPoP proof for each request
          try {
            DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(rsaKey, JWSAlgorithm.RS256);

            URI uri = new URI("/" + method.getFullMethodName());
            SignedJWT proof = dpopFactory.createDPoPJWT("POST", uri, t);
            headers.put(Metadata.Key.of("DPoP", Metadata.ASCII_STRING_MARSHALLER),
                proof.serialize());
          } catch (URISyntaxException e) {
            throw new RuntimeException("Invalid URI syntax for DPoP proof creation", e);
          } catch (JOSEException e) {
            throw new RuntimeException("Error creating DPoP proof", e);
          }



          super.start(responseListener, headers);
        }
      };
    }

    /**
     * Either fetches a new access token or returns the cached access token if it is still valid.
     *
     * @return The access token.
     */
    private AccessToken getToken() {
      try {

        // If the token is expired or initially null, get a new token
        if (isTokenExpired() | this.token == null) {

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
          TokenResponse tokenResponse;

          HTTPResponse httpResponse = httpRequest.send();

          tokenResponse = TokenResponse.parse(httpResponse);
          if (!tokenResponse.indicatesSuccess()) {
            ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
            throw new RuntimeException("Token request failed: " + error);
          }

          this.token = tokenResponse.toSuccessResponse().getTokens().getAccessToken();
          // DPoPAccessToken dPoPAccessToken = tokens.getDPoPAccessToken();



          if (token.getLifetime() != 0) {
            // Need some type of leeway but not sure whats best
            this.tokenExpiryTime = Instant.now().plusSeconds(token.getLifetime() / 3);
          }

        } else {
          // If the token is still valid or not initially null, return the cached token
          return this.token;
        }

      } catch (Exception e) {
        // TODO Auto-generated catch block
        throw new RuntimeException("failed to get token", e);
      }
      return this.token;
    }

    /**
     * Checks if the token has expired.
     *
     * @return true if the token has expired, false otherwise.
     */
    private boolean isTokenExpired() {
      return this.tokenExpiryTime != null && this.tokenExpiryTime.isBefore(Instant.now());
    }
  }

}


