package io.opentdf.platform.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TokenSourceTest {

    private static final String FAKE_TOKEN_RESPONSE =
            "{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";

    private TokenSource buildTokenSource(MockWebServer tokenServer, RSAKey rsaKey) throws Exception {
        return new TokenSource(
                new ClientSecretBasic(new ClientID("test-client"), new Secret("test-secret")),
                rsaKey,
                JWSAlgorithm.RS256,
                tokenServer.url("/token").uri(),
                new ClientCredentialsGrant(),
                null
        );
    }

    @Test
    void cachedNonceIsIncludedInNextDPoPProof() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            // Token endpoint queues two responses: one for initial fetch, one in case of re-fetch
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL testUrl = new URL("https://kas.example.com/kas");

            ts.cacheNonce(testUrl, "server-nonce-abc");

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(testUrl, "POST");
            SignedJWT dpopJwt = SignedJWT.parse(headers.getDpopHeader());
            String nonceClaim = dpopJwt.getJWTClaimsSet().getStringClaim("nonce");

            assertThat(nonceClaim).isEqualTo("server-nonce-abc");
        }
    }

    @Test
    void explicitNonceOverridesCachedNonce() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL testUrl = new URL("https://kas.example.com/kas");

            ts.cacheNonce(testUrl, "cached-nonce");

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(testUrl, "POST", "explicit-nonce");
            SignedJWT dpopJwt = SignedJWT.parse(headers.getDpopHeader());
            String nonceClaim = dpopJwt.getJWTClaimsSet().getStringClaim("nonce");

            assertThat(nonceClaim).isEqualTo("explicit-nonce");
        }
    }

    @Test
    void noNonceClaimWhenNoCachedNonce() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL testUrl = new URL("https://kas.example.com/kas");

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(testUrl, "POST");
            SignedJWT dpopJwt = SignedJWT.parse(headers.getDpopHeader());
            String nonceClaim = dpopJwt.getJWTClaimsSet().getStringClaim("nonce");

            assertThat(nonceClaim).isNull();
        }
    }
}
