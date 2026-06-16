package io.opentdf.platform.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    @Test
    void ecKeyGeneratesDPoPProof() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            TokenSource ts = new TokenSource(
                    new ClientSecretBasic(new ClientID("test-client"), new Secret("test-secret")),
                    ecKey,
                    JWSAlgorithm.ES256,
                    tokenServer.url("/token").uri(),
                    new ClientCredentialsGrant(),
                    null
            );
            URL testUrl = new URL("https://kas.example.com/kas");
            ts.cacheNonce(testUrl, "ec-nonce");

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(testUrl, "POST");
            assertThat(headers.getAuthHeader()).startsWith("DPoP ");

            SignedJWT dpopJwt = SignedJWT.parse(headers.getDpopHeader());
            assertThat(dpopJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
            assertThat(dpopJwt.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("ec-nonce");
        }
    }

    @Test
    void noncesAreIsolatedByOrigin() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            for (int i = 0; i < 4; i++) {
                tokenServer.enqueue(new MockResponse()
                        .setBody(FAKE_TOKEN_RESPONSE)
                        .setHeader("Content-Type", "application/json"));
            }
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL kasUrl = new URL("https://kas.example.com/kas");
            URL otherUrl = new URL("https://other.example.com/kas");

            ts.cacheNonce(kasUrl, "kas-nonce");

            TokenSource.AuthHeaders headersForKas = ts.getAuthHeaders(kasUrl, "POST");
            TokenSource.AuthHeaders headersForOther = ts.getAuthHeaders(otherUrl, "POST");

            String kasNonce = SignedJWT.parse(headersForKas.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce");
            String otherNonce = SignedJWT.parse(headersForOther.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce");

            assertThat(kasNonce).isEqualTo("kas-nonce");
            assertThat(otherNonce).isNull();
        }
    }

    @Test
    void noncesAreIsolatedByPort() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            for (int i = 0; i < 2; i++) {
                tokenServer.enqueue(new MockResponse()
                        .setBody(FAKE_TOKEN_RESPONSE)
                        .setHeader("Content-Type", "application/json"));
            }
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL port8080 = new URL("https://kas.example.com:8080/kas");
            URL port9090 = new URL("https://kas.example.com:9090/kas");

            ts.cacheNonce(port8080, "nonce-8080");
            TokenSource.AuthHeaders headers8080 = ts.getAuthHeaders(port8080, "POST");
            TokenSource.AuthHeaders headers9090 = ts.getAuthHeaders(port9090, "POST");

            assertThat(SignedJWT.parse(headers8080.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("nonce-8080");
            assertThat(SignedJWT.parse(headers9090.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce")).isNull();
        }
    }

    @Test
    void noncesAreIsolatedByScheme() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            for (int i = 0; i < 2; i++) {
                tokenServer.enqueue(new MockResponse()
                        .setBody(FAKE_TOKEN_RESPONSE)
                        .setHeader("Content-Type", "application/json"));
            }
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL httpsUrl = new URL("https://kas.example.com/kas");
            URL httpUrl = new URL("http://kas.example.com/kas");

            ts.cacheNonce(httpsUrl, "https-nonce");
            TokenSource.AuthHeaders headersHttps = ts.getAuthHeaders(httpsUrl, "POST");
            TokenSource.AuthHeaders headersHttp = ts.getAuthHeaders(httpUrl, "POST");

            assertThat(SignedJWT.parse(headersHttps.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("https-nonce");
            assertThat(SignedJWT.parse(headersHttp.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce")).isNull();
        }
    }

    @Test
    void noncesShareCacheForImplicitAndExplicitDefaultPort() throws Exception {
        // Pins the getDefaultPort() normalization in TokenSource.getOrigin —
        // https://host and https://host:443 must share a cache entry.
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL implicitPort = new URL("https://kas.example.com/kas");
            URL explicitPort = new URL("https://kas.example.com:443/kas");

            ts.cacheNonce(explicitPort, "shared-nonce");
            TokenSource.AuthHeaders headers = ts.getAuthHeaders(implicitPort, "POST");

            assertThat(SignedJWT.parse(headers.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("shared-nonce");
        }
    }

    @Test
    void emptyNonceIsNotCached() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL testUrl = new URL("https://kas.example.com/kas");

            ts.cacheNonce(testUrl, "");
            ts.cacheNonce(testUrl, null);

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(testUrl, "POST");
            String nonceClaim = SignedJWT.parse(headers.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce");

            assertThat(nonceClaim).isNull();
        }
    }

    @Test
    void getToken_retriesWithNonceOnUseDpopNonce() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            // First: 401 use_dpop_nonce
            tokenServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .addHeader("DPoP-Nonce", "retry-nonce-abc")
                    .setBody("{\"error\":\"use_dpop_nonce\",\"error_description\":\"nonce required\"}"));
            // Second: success
            tokenServer.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"real-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            URL resourceUrl = new URL("https://kas.example.com/kas");

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(resourceUrl, "POST");

            assertThat(headers.getAuthHeader()).isEqualTo("DPoP real-token");
            assertThat(tokenServer.getRequestCount()).isEqualTo(2);

            RecordedRequest first = tokenServer.takeRequest();
            String firstNonce = SignedJWT.parse(first.getHeader("DPoP"))
                    .getJWTClaimsSet().getStringClaim("nonce");
            assertThat(firstNonce).isNull();

            RecordedRequest second = tokenServer.takeRequest();
            String secondNonce = SignedJWT.parse(second.getHeader("DPoP"))
                    .getJWTClaimsSet().getStringClaim("nonce");
            assertThat(secondNonce).isEqualTo("retry-nonce-abc");
        }
    }

    @Test
    void getToken_throwsDescriptiveErrorWhenUseDpopNonceLacksHeader() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            // 401 use_dpop_nonce but NO DPoP-Nonce header
            tokenServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"use_dpop_nonce\",\"error_description\":\"nonce required\"}"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);

            assertThatThrownBy(() -> ts.getAuthHeaders(new URL("https://kas.example.com/kas"), "POST"))
                    .isInstanceOf(SDKException.class)
                    .satisfies(e -> assertThat(e.getMessage() + (e.getCause() != null ? e.getCause().getMessage() : ""))
                            .contains("use_dpop_nonce"));
        }
    }

    @Test
    void getToken_surfacesMalformedTokenResponseDistinctly() throws Exception {
        // Pre-fix every token-fetch failure surfaced as "failed to get token" with the
        // cause buried. After C3 the parse failure is attributed to the token endpoint.
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            // 200 with non-JSON body trips ParseException inside nimbus.
            tokenServer.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("this is not json"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);

            assertThatThrownBy(() -> ts.getAuthHeaders(new URL("https://kas.example.com/kas"), "POST"))
                    .isInstanceOf(SDKException.class)
                    .hasMessageContaining("malformed token response")
                    .hasMessageContaining(tokenServer.url("/token").toString());
        }
    }

    @Test
    void constructor_rejectsRsaKeyWithEcAlgorithm() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString()).generate();
        assertThatThrownBy(() -> new TokenSource(
                new ClientSecretBasic(new ClientID("c"), new Secret("s")),
                rsaKey, JWSAlgorithm.ES256,
                new URL("https://idp.example.com/token").toURI(),
                new ClientCredentialsGrant(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RSA")
                .hasMessageContaining("ES256");
    }

    @Test
    void constructor_rejectsEcKeyWithMismatchedCurveAlgorithm() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString()).generate();
        assertThatThrownBy(() -> new TokenSource(
                new ClientSecretBasic(new ClientID("c"), new Secret("s")),
                ecKey, JWSAlgorithm.ES384,
                new URL("https://idp.example.com/token").toURI(),
                new ClientCredentialsGrant(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("P-256")
                .hasMessageContaining("ES384");
    }

    @Test
    void constructor_rejectsUnsupportedJwkType() throws Exception {
        // OKP type — parsed from a static JWK to avoid pulling in the Tink dependency
        // that OctetKeyPairGenerator needs at runtime.
        JWK okp = JWK.parse("{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
                + "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\","
                + "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"}");
        assertThatThrownBy(() -> new TokenSource(
                new ClientSecretBasic(new ClientID("c"), new Secret("s")),
                okp, JWSAlgorithm.EdDSA,
                new URL("https://idp.example.com/token").toURI(),
                new ClientCredentialsGrant(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported JWK type");
    }

    @Test
    void getToken_usesProactivelyCachedNonce() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"proactive-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}"));
            tokenServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            // Pre-seed the cache for the token endpoint origin
            ts.cacheNonce(tokenServer.url("/token").url(), "proactive-nonce");

            ts.getAuthHeaders(new URL("https://kas.example.com/kas"), "POST");

            assertThat(tokenServer.getRequestCount()).isEqualTo(1);

            RecordedRequest request = tokenServer.takeRequest();
            String nonceClaim = SignedJWT.parse(request.getHeader("DPoP"))
                    .getJWTClaimsSet().getStringClaim("nonce");
            assertThat(nonceClaim).isEqualTo("proactive-nonce");
        }
    }
}
