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
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class DPoPRetryInterceptorTest {

    private static final String FAKE_TOKEN_RESPONSE =
            "{\"access_token\":\"test-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";

    private AuthInterceptor buildAuthInterceptor(MockWebServer tokenServer, RSAKey rsaKey) throws Exception {
        TokenSource ts = new TokenSource(
                new ClientSecretBasic(new ClientID("test-client"), new Secret("test-secret")),
                rsaKey,
                JWSAlgorithm.RS256,
                tokenServer.url("/token").uri(),
                new ClientCredentialsGrant(),
                null
        );
        return new AuthInterceptor(ts);
    }

    @Test
    void retryOn401WithDPoPNonce() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer();
             MockWebServer kasServer = new MockWebServer()) {
            // Queue multiple token responses (one for each getAuthHeaders call during retry)
            for (int i = 0; i < 5; i++) {
                tokenServer.enqueue(new MockResponse()
                        .setBody(FAKE_TOKEN_RESPONSE)
                        .setHeader("Content-Type", "application/json"));
            }
            tokenServer.start();

            // First request returns 401 + DPoP-Nonce; second returns 200
            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "server-issued-nonce"));
            kasServer.enqueue(new MockResponse().setResponseCode(200));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            Request request = new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build();
            Response response = client.newCall(request).execute();
            response.close();

            assertThat(kasServer.getRequestCount()).isEqualTo(2);
            assertThat(response.code()).isEqualTo(200);

            // Verify second request carries a DPoP proof with the nonce
            kasServer.takeRequest(); // consume first request
            RecordedRequest retryRequest = kasServer.takeRequest();
            String dpopHeader = retryRequest.getHeader("DPoP");
            assertThat(dpopHeader).isNotNull();

            SignedJWT dpopJwt = SignedJWT.parse(dpopHeader);
            String nonceClaim = dpopJwt.getJWTClaimsSet().getStringClaim("nonce");
            assertThat(nonceClaim).isEqualTo("server-issued-nonce");
        }
    }

    @Test
    void noRetryOn401WithoutDPoPNonce() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer();
             MockWebServer kasServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            kasServer.enqueue(new MockResponse().setResponseCode(401));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            Request request = new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build();
            Response response = client.newCall(request).execute();
            response.close();

            assertThat(kasServer.getRequestCount()).isEqualTo(1);
            assertThat(response.code()).isEqualTo(401);
        }
    }

    @Test
    void noRetryOnSuccessResponse() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer();
             MockWebServer kasServer = new MockWebServer()) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            kasServer.enqueue(new MockResponse().setResponseCode(200));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            Request request = new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build();
            Response response = client.newCall(request).execute();
            response.close();

            assertThat(kasServer.getRequestCount()).isEqualTo(1);
            assertThat(response.code()).isEqualTo(200);
        }
    }
}
