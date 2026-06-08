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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
    private final SSLSocketFactory sslSocketFactory;
    // Cache for server-issued nonces, keyed by origin (scheme://host:port)
    private final Map<String, String> nonceCache = new ConcurrentHashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(TokenSource.class);


    /**
     * Constructs a new TokenSource with the specified client authentication and RSA key.
     *
     * @param clientAuth        the client authentication to be used by the interceptor
     * @param rsaKey            the RSA key to be used by the interceptor
     * @param sslSocketFactory  Optional SSLSocketFactory for token endpoint requests
     */
    public TokenSource(ClientAuthentication clientAuth, RSAKey rsaKey, URI tokenEndpointURI, AuthorizationGrant authzGrant, SSLSocketFactory sslSocketFactory) {
        this.clientAuth = clientAuth;
        this.rsaKey = rsaKey;
        this.tokenEndpointURI = tokenEndpointURI;
        this.sslSocketFactory = sslSocketFactory;
        this.authzGrant = authzGrant;
        this.tokenExpiryTime = null;
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
        return getAuthHeaders(url, method, null);
    }

    /**
     * Get authorization headers for a request, including DPoP proof.
     *
     * @param url The URL being accessed
     * @param method The HTTP method
     * @param nonce Optional server-issued nonce to include in the proof
     * @return AuthHeaders containing Authorization and DPoP headers
     */
    public AuthHeaders getAuthHeaders(URL url, String method, String nonce) {
        // Get the access token
        AccessToken t = getToken();

        // Build the DPoP proof for each request
        String dpopProof;
        try {
            DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(rsaKey, JWSAlgorithm.RS256);

            // Get cached nonce if not explicitly provided
            if (nonce == null) {
                String origin = getOrigin(url);
                nonce = nonceCache.get(origin);
            }

            SignedJWT proof;
            if (nonce != null) {
                proof = dpopFactory.createDPoPJWT(method, url.toURI(), t, nonce);
            } else {
                proof = dpopFactory.createDPoPJWT(method, url.toURI(), t);
            }
            dpopProof = proof.serialize();
        } catch (URISyntaxException e) {
            throw new SDKException("Invalid URI syntax for DPoP proof creation", e);
        } catch (JOSEException e) {
            throw new SDKException("Error creating DPoP proof", e);
        }

        return new AuthHeaders(
                "DPoP " + t.getValue(),
                dpopProof);
    }

    /**
     * Cache a server-issued nonce for the given URL's origin.
     *
     * @param url The URL from which the nonce was received
     * @param nonce The nonce value to cache
     */
    public void cacheNonce(URL url, String nonce) {
        if (nonce != null && !nonce.isEmpty()) {
            String origin = getOrigin(url);
            nonceCache.put(origin, nonce);
            logger.trace("Cached DPoP nonce for origin: {}", origin);
        }
    }

    /**
     * Get the origin (scheme://host:port) from a URL for nonce caching.
     *
     * @param url The URL to extract origin from
     * @return The origin string
     */
    private String getOrigin(URL url) {
        int port = url.getPort();
        if (port == -1) {
            port = url.getDefaultPort();
        }
        return url.getProtocol() + "://" + url.getHost() + ":" + port;
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
                if (sslSocketFactory != null) {
                    httpRequest.setSSLSocketFactory(sslSocketFactory);
                }

                DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(rsaKey, JWSAlgorithm.RS256);

                SignedJWT proof = dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI());

                httpRequest.setDPoP(proof);
                TokenResponse tokenResponse;

                HTTPResponse httpResponse = httpRequest.send();

                tokenResponse = TokenResponse.parse(httpResponse);
                if (!tokenResponse.indicatesSuccess()) {
                    ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
                    throw new SDKException("failure to get token. description = [" + error.getDescription() + "] error code = [" + error.getCode() + "] error uri = [" + error.getURI() + "]");
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
            throw new SDKException("failed to get token", e);
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
