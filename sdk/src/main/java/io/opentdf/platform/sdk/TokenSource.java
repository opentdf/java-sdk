package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
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
import com.nimbusds.openid.connect.sdk.Nonce;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.MalformedURLException;
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
    static final String SCHEME_DPOP = "DPoP";
    static final String SCHEME_BEARER = "Bearer";

    private Instant tokenExpiryTime;
    private AccessToken token;
    private String tokenScheme;
    private final ClientAuthentication clientAuth;
    private final JWK dpopJwk;
    private final JWSAlgorithm dpopAlg;
    private final URI tokenEndpointURI;
    private final AuthorizationGrant authzGrant;
    private final SSLSocketFactory sslSocketFactory;
    // Cache for server-issued nonces, keyed by origin (scheme://host:port)
    private final Map<String, String> nonceCache = new ConcurrentHashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(TokenSource.class);


    /**
     * Constructs a new TokenSource with the specified client authentication and DPoP key.
     *
     * @param clientAuth        the client authentication to be used by the interceptor
     * @param dpopJwk    the JWK (RSA or EC) to use for DPoP proof generation
     * @param dpopAlg    the JWS algorithm matching the key type
     * @param sslSocketFactory  Optional SSLSocketFactory for token endpoint requests
     */
    public TokenSource(ClientAuthentication clientAuth, JWK dpopJwk, JWSAlgorithm dpopAlg, URI tokenEndpointURI, AuthorizationGrant authzGrant, SSLSocketFactory sslSocketFactory) {
        DpopKeyValidation.validate(dpopJwk, dpopAlg);
        this.clientAuth = clientAuth;
        this.dpopJwk = dpopJwk;
        this.dpopAlg = dpopAlg;
        this.tokenEndpointURI = tokenEndpointURI;
        this.sslSocketFactory = sslSocketFactory;
        this.authzGrant = authzGrant;
        this.tokenExpiryTime = null;
    }

    class AuthHeaders {
        private final String authHeader;
        @Nullable
        private final String dpopHeader;

        public AuthHeaders(String authHeader, @Nullable String dpopHeader) {
            this.authHeader = authHeader;
            this.dpopHeader = dpopHeader;
        }

        public String getAuthHeader() {
            return authHeader;
        }

        @Nullable
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

        // If the AS returned a plain bearer token, send it as a bearer credential
        // without a DPoP proof. Sending "Authorization: DPoP <bearer>" is a misuse
        // of the scheme and resource servers that enforce DPoP will reject it.
        if (SCHEME_BEARER.equals(tokenScheme)) {
            return new AuthHeaders("Bearer " + t.getValue(), null);
        }

        // Build the DPoP proof for each request
        String dpopProof;
        try {
            DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(dpopJwk, dpopAlg);

            // Get cached nonce if not explicitly provided
            if (nonce == null) {
                String origin = getOrigin(url);
                nonce = nonceCache.get(origin);
            }

            SignedJWT proof;
            URI htu = htuOf(url.toURI());
            if (nonce != null) {
                proof = dpopFactory.createDPoPJWT(method, htu, t, new Nonce(nonce));
            } else {
                proof = dpopFactory.createDPoPJWT(method, htu, t);
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

    // RFC 9449 §4.2: the htu claim is the request URI with query and fragment removed.
    // Nimbus rejects any URI carrying a query, so strip both before handing it off.
    private static URI htuOf(URI uri) {
        if (uri.getRawQuery() == null && uri.getRawFragment() == null) {
            return uri;
        }
        try {
            return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), null, null);
        } catch (URISyntaxException e) {
            throw new SDKException("failed to normalize URI for DPoP htu claim: " + uri, e);
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

                DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(dpopJwk, dpopAlg);

                // Proactively use any cached nonce for the token endpoint origin (RFC 9449 §8.2)
                URL tokenEndpointUrl = tokenEndpointURI.toURL();
                String cachedNonce = nonceCache.get(getOrigin(tokenEndpointUrl));

                TokenRequest tokenRequest = new TokenRequest(this.tokenEndpointURI, clientAuth, authzGrant, null);
                HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
                if (sslSocketFactory != null) {
                    httpRequest.setSSLSocketFactory(sslSocketFactory);
                }
                URI tokenHtu = htuOf(httpRequest.getURI());
                SignedJWT proof = (cachedNonce != null)
                        ? dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), tokenHtu, new Nonce(cachedNonce))
                        : dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), tokenHtu);
                httpRequest.setDPoP(proof);

                HTTPResponse httpResponse = httpRequest.send();

                TokenResponse tokenResponse = TokenResponse.parse(httpResponse);

                // RFC 9449 §8.2: if AS requires a nonce, cache it and retry once
                if (!tokenResponse.indicatesSuccess()) {
                    ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
                    if ("use_dpop_nonce".equals(error.getCode())) {
                        String dpopNonce = httpResponse.getHeaderValue("DPoP-Nonce");
                        if (dpopNonce != null) {
                            cacheNonce(tokenEndpointUrl, dpopNonce);
                            TokenRequest retryRequest = new TokenRequest(tokenEndpointURI, clientAuth, authzGrant, null);
                            HTTPRequest retryHttpRequest = retryRequest.toHTTPRequest();
                            if (sslSocketFactory != null) {
                                retryHttpRequest.setSSLSocketFactory(sslSocketFactory);
                            }
                            SignedJWT retryProof = dpopFactory.createDPoPJWT(
                                    retryHttpRequest.getMethod().name(),
                                    htuOf(retryHttpRequest.getURI()),
                                    new Nonce(dpopNonce));
                            retryHttpRequest.setDPoP(retryProof);
                            httpResponse = retryHttpRequest.send();
                            tokenResponse = TokenResponse.parse(httpResponse);
                            // Cache any nonce rotation from the AS (RFC 9449 §8.2)
                            String rotatedNonce = httpResponse.getHeaderValue("DPoP-Nonce");
                            if (rotatedNonce != null) {
                                cacheNonce(tokenEndpointUrl, rotatedNonce);
                            }
                        } else {
                            logger.warn("token endpoint {} returned use_dpop_nonce but did not supply a DPoP-Nonce response header",
                                    tokenEndpointURI);
                        }
                    }
                    if (!tokenResponse.indicatesSuccess()) {
                        ErrorObject finalError = tokenResponse.toErrorResponse().getErrorObject();
                        throw new SDKException("failure to get token. description = [" + finalError.getDescription()
                                + "] error code = [" + finalError.getCode()
                                + "] error uri = [" + finalError.getURI() + "]");
                    }
                }

                var tokens = tokenResponse.toSuccessResponse().getTokens();
                boolean asAssertsDpop = tokens.getDPoPAccessToken() != null;
                if (asAssertsDpop) {
                    logger.trace("retrieved a new DPoP access token");
                } else if (tokens.getAccessToken() != null) {
                    logger.trace("retrieved a new access token");
                } else {
                    logger.warn("token endpoint {} returned a success response with an unknown access token type",
                            tokenEndpointURI);
                }

                this.token = tokens.getAccessToken();
                if (this.token == null) {
                    throw new SDKException("token endpoint " + tokenEndpointURI
                            + " returned a success response with no access token");
                }
                this.tokenScheme = asAssertsDpop ? SCHEME_DPOP : SCHEME_BEARER;
                if (!asAssertsDpop) {
                    logger.warn("token endpoint {} returned a non-DPoP-bound access token (token_type=Bearer) despite"
                            + " DPoP proof — falling back to Bearer scheme. Check the IdP DPoP configuration.",
                            tokenEndpointURI);
                }

                if (token.getLifetime() != 0) {
                    this.tokenExpiryTime = Instant.now().plusSeconds(token.getLifetime() / 3);
                }

            } else {
                // If the token is still valid or not initially null, return the cached token
                return this.token;
            }

        } catch (SDKException e) {
            // Already shaped for the caller — don't double-wrap.
            throw e;
        } catch (MalformedURLException e) {
            throw new SDKException("invalid token endpoint URL: " + tokenEndpointURI, e);
        } catch (IOException e) {
            throw new SDKException("network error contacting token endpoint " + tokenEndpointURI, e);
        } catch (JOSEException e) {
            throw new SDKException("DPoP proof generation failed for token endpoint " + tokenEndpointURI, e);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new SDKException("malformed token response from " + tokenEndpointURI, e);
        } catch (RuntimeException e) {
            throw new SDKException("unexpected error fetching token from " + tokenEndpointURI, e);
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
