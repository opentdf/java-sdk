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
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class DPoPRetryInterceptorTest {

    private static final String FAKE_TOKEN_RESPONSE =
            "{\"access_token\":\"test-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}";

    private static final String BEARER_TOKEN_RESPONSE =
            "{\"access_token\":\"test-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";

    private AuthInterceptor buildAuthInterceptor(MockWebServer tokenServer, RSAKey rsaKey) {
        return new AuthInterceptor(buildTokenSource(tokenServer, rsaKey));
    }

    private TokenSource buildTokenSource(MockWebServer tokenServer, RSAKey rsaKey) {
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

            // First request returns 401 + DPoP-Nonce + DPoP nonce challenge; second returns 200
            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "server-issued-nonce")
                    .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""));
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
    void retryDowngradesToBearerAndDropsStaleDpopProof() throws Exception {
        // Regression guard for AuthInterceptor.dpopRetryInterceptor's removeHeader("DPoP").
        // When the token refreshed on retry comes back as a plain Bearer token (the AS did
        // not bind it to the DPoP key), the retried request must send Authorization: Bearer
        // with NO DPoP header. Without the removeHeader, the original request's stale DPoP
        // proof would ride along next to a Bearer credential -- an RFC 9449 scheme misuse
        // that DPoP-enforcing resource servers reject.
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer();
             MockWebServer kasServer = new MockWebServer()) {
            // The single token fetched during the retry is a plain Bearer token.
            tokenServer.enqueue(new MockResponse()
                    .setBody(BEARER_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            // First request returns 401 + DPoP-Nonce + DPoP nonce challenge; second returns 200
            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "server-issued-nonce")
                    .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""));
            kasServer.enqueue(new MockResponse().setResponseCode(200));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            // Seed the initial request with a stale DPoP proof + DPoP Authorization so the
            // downgrade genuinely has a proof to strip (guards against a vacuously-null check).
            Request request = new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .header("Authorization", "DPoP stale-token")
                    .header("DPoP", "stale-proof")
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build();
            Response response = client.newCall(request).execute();
            response.close();

            assertThat(response.code()).isEqualTo(200);
            assertThat(kasServer.getRequestCount()).isEqualTo(2);
            // Only one credential refresh happens on retry.
            assertThat(tokenServer.getRequestCount()).isEqualTo(1);

            kasServer.takeRequest(); // consume first request
            RecordedRequest retryRequest = kasServer.takeRequest();
            assertThat(retryRequest.getHeader("Authorization")).startsWith("Bearer ");
            // The stale proof must be gone: no DPoP header paired with a Bearer credential.
            assertThat(retryRequest.getHeader("DPoP")).isNull();
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
    void onlyRetriesOnceWhenSecondResponseAlsoChallengesWithNonce() throws Exception {
        // Pins the single-retry guarantee: even if the retry response is also a
        // 401 + DPoP-Nonce + use_dpop_nonce challenge, no further retry is attempted.
        // This protects against an infinite-retry loop if an AS misbehaves or rotates
        // nonces faster than the client can spend them. The persistent challenge must
        // also be logged at WARN so the double failure is visible rather than a silent 401.
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer();
             MockWebServer kasServer = new MockWebServer();
             LogCapture logs = LogCapture.attach(AuthInterceptor.class)) {
            tokenServer.enqueue(new MockResponse()
                    .setBody(FAKE_TOKEN_RESPONSE)
                    .setHeader("Content-Type", "application/json"));
            tokenServer.start();

            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "first-nonce")
                    .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""));
            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "second-nonce")
                    .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""));
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
            assertThat(response.code()).isEqualTo(401);
            assertThat(logs.warnings()).anyMatch(m -> m.contains("persisted after retry"));
        }
    }

    @Test
    void concurrentRequestsAllRetrySuccessfully() throws Exception {
        // Smoke test: drive 10 parallel requests through the retry interceptor, each of
        // which sees a 401+nonce followed by a 200. All 10 must eventually return 200
        // and each retry must carry a DPoP-Nonce claim. Regressions in the cross-thread
        // safety of the nonce cache or interceptor state should surface here.
        final int parallelism = 10;
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        try (MockWebServer tokenServer = new MockWebServer();
             MockWebServer kasServer = new MockWebServer()) {
            // One token response per request — the cache keeps us to one in practice,
            // but enqueue enough that any per-thread re-fetch doesn't deadlock the test.
            for (int i = 0; i < parallelism * 2; i++) {
                tokenServer.enqueue(new MockResponse()
                        .setBody(FAKE_TOKEN_RESPONSE)
                        .setHeader("Content-Type", "application/json"));
            }
            tokenServer.start();

            // A FIFO queue can't deliver alternating 401/200 reliably under concurrent
            // load — by the time request N's retry arrives, request N+1's first attempt
            // may have already consumed N's 200. Use a stateful dispatcher that decides
            // based on whether the request already carries a nonce.
            kasServer.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    String dpop = request.getHeader("DPoP");
                    boolean hasNonce = false;
                    if (dpop != null) {
                        try {
                            hasNonce = SignedJWT.parse(dpop)
                                    .getJWTClaimsSet().getStringClaim("nonce") != null;
                        } catch (Exception e) {
                            // Malformed/unparseable proof simply counts as "no nonce present".
                        }
                    }
                    if (hasNonce) {
                        return new MockResponse().setResponseCode(200);
                    }
                    return new MockResponse()
                            .setResponseCode(401)
                            .addHeader("DPoP-Nonce", "concurrent-nonce")
                            .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
                }
            });
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            ExecutorService pool = Executors.newFixedThreadPool(parallelism);
            try {
                List<Callable<Integer>> tasks = new ArrayList<>();
                for (int i = 0; i < parallelism; i++) {
                    tasks.add(() -> {
                        Request request = new Request.Builder()
                                .url(kasServer.url("/kas/rewrap"))
                                .post(okhttp3.RequestBody.create(new byte[0]))
                                .build();
                        try (Response response = client.newCall(request).execute()) {
                            return response.code();
                        }
                    });
                }
                List<Future<Integer>> results = pool.invokeAll(tasks, 30, TimeUnit.SECONDS);
                for (Future<Integer> f : results) {
                    assertThat(f.get()).isEqualTo(200);
                }
            } finally {
                pool.shutdownNow();
            }

            // Each request produced a 401 + a retry: 2 * parallelism total.
            assertThat(kasServer.getRequestCount()).isEqualTo(parallelism * 2);

            // Every retry must carry a nonce — pin that the cross-thread URL/nonce
            // bookkeeping never produced a retry without one.
            int retriesWithNonce = 0;
            int totalRetries = 0;
            for (int i = 0; i < parallelism * 2; i++) {
                RecordedRequest recorded = kasServer.takeRequest();
                String dpop = recorded.getHeader("DPoP");
                if (dpop == null) {
                    continue;
                }
                String nonce = SignedJWT.parse(dpop).getJWTClaimsSet().getStringClaim("nonce");
                if (nonce != null) {
                    retriesWithNonce++;
                }
                if (nonce != null) {
                    totalRetries++;
                }
            }
            assertThat(totalRetries).isEqualTo(parallelism);
            assertThat(retriesWithNonce).isEqualTo(parallelism);
        }
    }

    @Test
    void noRetryOn401WithDPoPNonceButNoChallenge() throws Exception {
        // A bare DPoP-Nonce header on a 401 (no WWW-Authenticate) must not trigger a retry —
        // otherwise any rogue origin can poison the nonce cache and burn a token round-trip.
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

            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "spurious-nonce"));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            Response response = client.newCall(new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build()).execute();
            response.close();

            assertThat(kasServer.getRequestCount()).isEqualTo(1);
            assertThat(response.code()).isEqualTo(401);
        }
    }

    @Test
    void noRetryOn401WithNonDpopChallenge() throws Exception {
        // WWW-Authenticate: Basic must not trigger a DPoP retry even if DPoP-Nonce is present.
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

            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "spurious-nonce")
                    .addHeader("WWW-Authenticate", "Basic realm=\"x\""));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            Response response = client.newCall(new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build()).execute();
            response.close();

            assertThat(kasServer.getRequestCount()).isEqualTo(1);
            assertThat(response.code()).isEqualTo(401);
        }
    }

    @Test
    void noRetryOn401WithDpopErrorOtherThanUseDpopNonce() throws Exception {
        // RFC 9449 §9 only signals retry on error=use_dpop_nonce. Other DPoP errors
        // (invalid_token, insufficient_scope, etc.) must surface to the caller.
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

            kasServer.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .addHeader("DPoP-Nonce", "fresh-nonce")
                    .addHeader("WWW-Authenticate", "DPoP error=\"invalid_token\""));
            kasServer.start();

            AuthInterceptor authInterceptor = buildAuthInterceptor(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(authInterceptor.dpopRetryInterceptor())
                    .build();

            Response response = client.newCall(new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build()).execute();
            response.close();

            assertThat(kasServer.getRequestCount()).isEqualTo(1);
            assertThat(response.code()).isEqualTo(401);
        }
    }

    @Test
    void rotatedNonceFromSuccessfulResponseIsCachedForNextRequest() throws Exception {
        // RFC 9449 §9: any response (including 200) may rotate the nonce. The retry
        // interceptor must pick that up so the *next* request picks it from the cache.
        // Note: the retry interceptor itself does not stamp DPoP headers on the initial
        // request — those come from the auth path that builds the request — so we
        // verify cache population by querying the TokenSource directly afterward.
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

            kasServer.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("DPoP-Nonce", "rotated-nonce"));
            kasServer.start();

            TokenSource ts = buildTokenSource(tokenServer, rsaKey);
            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(new AuthInterceptor(ts).dpopRetryInterceptor())
                    .build();

            client.newCall(new Request.Builder()
                    .url(kasServer.url("/kas/rewrap"))
                    .post(okhttp3.RequestBody.create(new byte[0]))
                    .build()).execute().close();

            TokenSource.AuthHeaders headers = ts.getAuthHeaders(
                    kasServer.url("/kas/rewrap").url(), "POST");
            String nonceClaim = SignedJWT.parse(headers.getDpopHeader())
                    .getJWTClaimsSet().getStringClaim("nonce");
            assertThat(nonceClaim).isEqualTo("rotated-nonce");
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

    /**
     * Captures WARN-and-above log messages from a target logger for the duration of a
     * test, then detaches on close. Used to assert that a failure is surfaced in the
     * logs rather than swallowed silently.
     */
    private static final class LogCapture extends AbstractAppender implements AutoCloseable {
        private final List<String> messages = new CopyOnWriteArrayList<>();
        private final LoggerConfig loggerConfig;

        private LogCapture(LoggerConfig loggerConfig) {
            super("test-capture", null, null, false, Property.EMPTY_ARRAY);
            this.loggerConfig = loggerConfig;
        }

        static LogCapture attach(Class<?> target) {
            LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
            LoggerConfig config = ctx.getConfiguration().getLoggerConfig(target.getName());
            LogCapture appender = new LogCapture(config);
            appender.start();
            config.addAppender(appender, Level.WARN, null);
            return appender;
        }

        @Override
        public void append(LogEvent event) {
            messages.add(event.getMessage().getFormattedMessage());
        }

        List<String> warnings() {
            return messages;
        }

        @Override
        public void close() {
            loggerConfig.removeAppender(getName());
            stop();
        }
    }
}
