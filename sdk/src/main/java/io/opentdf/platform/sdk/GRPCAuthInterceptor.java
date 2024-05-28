package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import nl.altindag.ssl.SSLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;

/**
 * The GRPCAuthInterceptor class is responsible for intercepting client calls before they are sent
 * to the server. It adds authentication headers to the requests by fetching and caching access
 * tokens.
 */
class GRPCAuthInterceptor implements ClientInterceptor {
    private Instant tokenExpiryTime;
    private AccessToken token;
    private final ClientAuthentication clientAuth;
    private final RSAKey rsaKey;
    private final URI tokenEndpointURI;
    private SSLFactory sslFactory;
    private static final Logger logger = LoggerFactory.getLogger(GRPCAuthInterceptor.class);


    /**
     * Constructs a new GRPCAuthInterceptor with the specified client authentication and RSA key.
     *
     * @param clientAuth the client authentication to be used by the interceptor
     * @param rsaKey     the RSA key to be used by the interceptor
     * @param sslFactory Optional SSLFactory for Requests
     */
    public GRPCAuthInterceptor(ClientAuthentication clientAuth, RSAKey rsaKey, URI tokenEndpointURI, SSLFactory sslFactory) {
        this.clientAuth = clientAuth;
        this.rsaKey = rsaKey;
        this.tokenEndpointURI = tokenEndpointURI;
        this.sslFactory = sslFactory;
    }

    /**
     * Intercepts the client call before it is sent to the server.
     *
     * @param method      The method descriptor for the call.
     * @param callOptions The call options for the call.
     * @param next        The next channel in the channel pipeline.
     * @param <ReqT>      The type of the request message.
     * @param <RespT>     The type of the response message.
     * @return A client call with the intercepted behavior.
     */
    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method,
                                                               CallOptions callOptions, Channel next) {
        return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, callOptions)) {
            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
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
    private synchronized AccessToken getToken() {
        try {
            // If the token is expired or initially null, get a new token
            if (token == null || isTokenExpired()) {

                logger.trace("The current access token is expired or empty, getting a new one");

                // Construct the client credentials grant
                AuthorizationGrant clientGrant = new ClientCredentialsGrant();

                // Make the token request
                TokenRequest tokenRequest = new TokenRequest(this.tokenEndpointURI,
                        clientAuth, clientGrant, null);
                HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
                if(sslFactory!=null){
                    httpRequest.setSSLSocketFactory(sslFactory.getSslSocketFactory());
                }

                DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(rsaKey, JWSAlgorithm.RS256);

                SignedJWT proof = dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI());

                httpRequest.setDPoP(proof);
                TokenResponse tokenResponse;

                HTTPResponse httpResponse = httpRequest.send();

                tokenResponse = TokenResponse.parse(httpResponse);
                if (!tokenResponse.indicatesSuccess()) {
                    ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
                    throw new RuntimeException("Token request failed: " + error);
                }


                var tokens = tokenResponse.toSuccessResponse().getTokens();
                if (tokens.getDPoPAccessToken() != null) {
                    logger.trace("retrieved a new DPoP access token");
                } else if (tokens.getAccessToken() != null) {
                    logger.trace("retrieved a new access token");
                } else {
                    logger.trace("got an access token of unknown type");
                }

                this.token = tokens.getAccessToken();

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
