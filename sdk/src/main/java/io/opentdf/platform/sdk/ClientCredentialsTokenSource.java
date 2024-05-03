package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;

public class ClientCredentialsTokenSource implements TokenSource {

    private AccessToken accessToken = null;
    private Instant tokenExpiryTime = null;
    private final ClientAuthentication clientAuth;
    private final DPoPProofFactory dPoPProofFactory;
    private final URI tokenEndpointURI;


    public ClientCredentialsTokenSource(ClientAuthentication clientAuth, DPoPProofFactory dPoPProofFactory, URI tokenEndpointURI) {
        this.clientAuth = clientAuth;
        this.dPoPProofFactory = dPoPProofFactory;
        this.tokenEndpointURI = tokenEndpointURI;
    }

    @Override
    public synchronized AuthTokens getAuthTokens(String method, URI resource) {
        if (accessToken == null || isTokenExpired()) {
            fetchNewToken();
        }
        SignedJWT jwt;
        try {
            jwt = dPoPProofFactory.createDPoPJWT(method, resource);
        } catch (JOSEException e) {
            throw new SDKException("error creating DPoP proof", e);
        }

        return new AuthTokens(accessToken.getValue(), jwt.serialize());
    }

    private void fetchNewToken() {
        // Construct the client credentials grant
        AuthorizationGrant clientGrant = new ClientCredentialsGrant();

        // Make the token request
        TokenRequest tokenRequest = new TokenRequest(this.tokenEndpointURI,
                clientAuth, clientGrant, null);
        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();


        SignedJWT proof;
        try {
            proof = dPoPProofFactory.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI());
        } catch (JOSEException e) {
            throw new SDKException("error creatign dpop proof", e);
        }

        httpRequest.setDPoP(proof);

        HTTPResponse httpResponse;
        try {
            httpResponse = httpRequest.send();
        } catch (IOException e) {
            throw new SDKException("error making call to IdP", e);
        }

        TokenResponse tokenResponse;
        try {
            tokenResponse = TokenResponse.parse(httpResponse);
        } catch (ParseException e) {
            throw new SDKException("error parsing response from IdP", e);
        }
        if (!tokenResponse.indicatesSuccess()) {
            ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
            throw new RuntimeException("Token request failed: " + error);
        }

        accessToken = tokenResponse.toSuccessResponse().getTokens().getAccessToken();

        if (accessToken.getLifetime() != 0) {
            this.tokenExpiryTime = Instant.now().plusSeconds(accessToken.getLifetime() - 60);
        }
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
