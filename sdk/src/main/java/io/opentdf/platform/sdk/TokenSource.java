package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import nl.altindag.ssl.SSLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Instant;

/**
 * The TokenSource class is responsible for providing authorization tokens. It handles
 * timeouts and creating OIDC calls. It is thread-safe.
 */
class TokenSource {
    private Instant tokenExpiryTime;
    private AccessToken token;
    private final ClientAuthentication clientAuth;
    private final RSAKey rsaKey;
    private final URI tokenEndpointURI;
    private final AuthorizationGrant authzGrant;
    private final SSLFactory sslFactory;
    private static final Logger logger = LoggerFactory.getLogger(TokenSource.class);


    /**
     * Constructs a new TokenSource with the specified client authentication and RSA key.
     *
     * @param clientAuth the client authentication to be used by the interceptor
     * @param rsaKey     the RSA key to be used by the interceptor
     * @param sslFactory Optional SSLFactory for Requests
     */
    public TokenSource(ClientAuthentication clientAuth, RSAKey rsaKey, URI tokenEndpointURI, AuthorizationGrant authzGrant, SSLFactory sslFactory) {
        this.clientAuth = clientAuth;
        this.rsaKey = rsaKey;
        this.tokenEndpointURI = tokenEndpointURI;
        this.sslFactory = sslFactory;
        this.authzGrant = authzGrant;
    }

    class AuthHeaders {
        private final String authHeader;
        private final String dpopHeader;

        public AuthHeaders(String authHeader, String dpopHeader) {
            this.authHeader = authHeader;
            this.dpopHeader = dpopHeader;
        }

        public String getAuthHeader() {
            return authHeader;
        }

        public String getDpopHeader() {
            return dpopHeader;
        }
    }

    public AuthHeaders getAuthHeaders(URL url, String method) {
        // Get the access token
        AccessToken t = getToken();

        // Build the DPoP proof for each request
        String dpopProof;
        try {
            DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(rsaKey, JWSAlgorithm.RS256);
            SignedJWT proof = dpopFactory.createDPoPJWT(method, url.toURI(), t);
            dpopProof = proof.serialize();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Invalid URI syntax for DPoP proof creation", e);
        } catch (JOSEException e) {
            throw new RuntimeException("Error creating DPoP proof", e);
        }

        return new AuthHeaders(
                "DPoP " + t.getValue(),
                dpopProof);
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

                // Make the token request
                TokenRequest tokenRequest = new TokenRequest(this.tokenEndpointURI,
                        clientAuth, authzGrant, null);
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
