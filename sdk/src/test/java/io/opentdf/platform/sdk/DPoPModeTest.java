package io.opentdf.platform.sdk;

import com.google.protobuf.ListValue;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URL;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static io.opentdf.platform.sdk.DPoPModeResolver.WELL_KNOWN_CONFIGURATION_PROCEDURE;
import static io.opentdf.platform.sdk.DPoPModeResolver.PROTECTED_RESOURCE_PATH;
import static io.opentdf.platform.sdk.DPoPModeResolver.RETRY_INTERVAL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * DSPX-5640: the SDK picks RFC 9449 or legacy DPoP headers from what each server advertises.
 */
class DPoPModeTest {
    private static final String RPC_PATH = "/kas.AccessService/Rewrap";
    private static final String DPOP_TOKEN_RESPONSE =
            "{\"access_token\":\"test-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}";
    private static final String BEARER_TOKEN_RESPONSE =
            "{\"access_token\":\"test-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
    private static final String ALGS = "\"dpop_signing_alg_values_supported\":[\"ES256\",\"RS256\"]";

    private static RSAKey rsaKey;

    private MockWebServer tokenServer;
    private MockWebServer resourceServer;
    // Well-known documents the resource server publishes, keyed by path; absent paths 404.
    private final Map<String, MockResponse> wellKnown = new ConcurrentHashMap<>();
    private final List<RecordedRequest> discoveryRequests = new CopyOnWriteArrayList<>();
    private final AtomicBoolean challengeNextCall = new AtomicBoolean();
    private static final Duration TTL = Duration.ofMinutes(5);
    // Starts near overflow so expiry checks must tolerate a wrapping nanoTime.
    private final AtomicLong nanos = new AtomicLong(Long.MAX_VALUE - TTL.toNanos() / 2);

    @BeforeAll
    static void generateKey() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyID(UUID.randomUUID().toString()).generate();
    }

    @BeforeEach
    void startServers() throws Exception {
        tokenServer = new MockWebServer();
        tokenServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return json(DPOP_TOKEN_RESPONSE);
            }
        });
        tokenServer.start();

        resourceServer = new MockWebServer();
        resourceServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String path = request.getPath();
                if (isDiscovery(path)) {
                    discoveryRequests.add(request);
                    return wellKnown.getOrDefault(path, new MockResponse().setResponseCode(404));
                }
                if (challengeNextCall.getAndSet(false)) {
                    return new MockResponse()
                            .setResponseCode(401)
                            .addHeader("DPoP-Nonce", "server-nonce")
                            .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
                }
                return new MockResponse().setResponseCode(200);
            }
        });
        resourceServer.start();
    }

    @AfterEach
    void stopServers() throws Exception {
        tokenServer.shutdown();
        resourceServer.shutdown();
    }

    @Test
    void wellKnownDpopBlockOnly() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{\"dpop\":{\"rfc9449\":true}}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void wellKnownDpopBlockOverridesTopLevelAlgs() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                json("{\"configuration\":{\"dpop\":{\"rfc9449\":false}," + ALGS + "}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
    }

    @Test
    void dpopBlockWithoutABooleanFallsBackToAlgs() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                json("{\"configuration\":{\"dpop\":{\"rfc9449\":\"yes\"}," + ALGS + "}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);

        Struct noBool = Struct.newBuilder()
                .putFields("dpop", Value.newBuilder().setStructValue(Struct.getDefaultInstance()).build())
                .putFields("dpop_signing_alg_values_supported", Value.newBuilder().setListValue(
                        ListValue.newBuilder().addValues(Value.newBuilder().setStringValue("ES256"))).build())
                .build();
        assertThat(DPoPModeResolver.advertisesRfc9449(noBool)).isTrue();
    }

    @Test
    void declinedInWellKnownStillHonorsProtectedResourceMetadata() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{\"dpop\":{\"rfc9449\":false}}}"));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
    }

    @ParameterizedTest
    @ValueSource(ints = {404, 405, 501})
    void wellKnownWithoutTheEndpointIsConclusive(int status) {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, new MockResponse().setResponseCode(status));
        assertCachedFor(TTL);
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403, 429, 500, 503})
    void wellKnownErrorStatusIsRetried(int status) {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, new MockResponse().setResponseCode(status));
        assertCachedFor(RETRY_INTERVAL);
    }

    @Test
    void wellKnownRedirectIsNotFollowedAndIsRetried() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                new MockResponse().setResponseCode(302).setHeader("Location", "/.well-known/elsewhere"));
        wellKnown.put("/.well-known/elsewhere", json("{\"configuration\":{" + ALGS + "}}"));
        assertCachedFor(RETRY_INTERVAL);
        assertThat(discoveredPaths()).doesNotContain("/.well-known/elsewhere");
    }

    @Test
    void oversizedWellKnownIsRetried() {
        String padding = "x".repeat(1 << 20);
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                json("{\"configuration\":{" + ALGS + "},\"padding\":\"" + padding + "\"}"));
        assertCachedFor(RETRY_INTERVAL);
    }

    @Test
    void discoveryTimesOut() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        DPoPModeResolver resolver = new DPoPModeResolver(DPoPMode.AUTO, new OkHttpClient(), TTL, nanos::get,
                Duration.ofMillis(200));
        long start = System.nanoTime();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));
        // The deadline covers the whole discovery, so the metadata request is never sent.
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void concurrentFirstRequestsShareOneDiscovery() throws Exception {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                json("{\"configuration\":{" + ALGS + "}}").setHeadersDelay(300, TimeUnit.MILLISECONDS));
        DPoPModeResolver resolver = autoResolver();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<DPoPMode>> results = new java.util.ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    return resolver.modeFor(rpcUrl());
                }));
            }
            start.countDown();
            for (Future<DPoPMode> result : results) {
                assertThat(result.get(10, TimeUnit.SECONDS)).isEqualTo(DPoPMode.RFC9449);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void interruptedCallerFailsButDiscoveryCompletes() throws Exception {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                json("{\"configuration\":{" + ALGS + "}}").setHeadersDelay(500, TimeUnit.MILLISECONDS));
        DPoPModeResolver resolver = autoResolver();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean stillInterrupted = new AtomicBoolean();
        Thread caller = new Thread(() -> {
            try {
                resolver.modeFor(rpcUrl());
            } catch (SDKException e) {
                failure.set(e);
                stillInterrupted.set(Thread.currentThread().isInterrupted());
            }
        });
        caller.start();
        Thread.sleep(100);
        caller.interrupt();
        caller.join(5_000);

        assertThat(failure.get()).isInstanceOf(SDKException.class).hasCauseInstanceOf(InterruptedException.class);
        assertThat(stillInterrupted).isTrue();
        // The shared discovery wasn't cancelled with the caller, and its answer is cached.
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void wellKnownTopLevelAlgsOnly() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{\"platform_issuer\":\"x\"," + ALGS + "}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void wellKnownEmptyAlgsIsNotAnAdvertisement() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE,
                json("{\"configuration\":{\"dpop_signing_alg_values_supported\":[]}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void protectedResourceMetadataOnly() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{\"platform_issuer\":\"x\"}}"));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{\"resource\":\"x\"," + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void protectedResourceMetadataWithoutOpentdfConfiguration() {
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
    }

    @Test
    void bothAdvertisedStopsAtWellKnown() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{\"dpop\":{\"rfc9449\":true}," + ALGS + "}}"));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void neitherAdvertisedSendsLegacyHeaders() throws Exception {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{\"platform_issuer\":\"x\"}}"));
        TokenSource ts = tokenSource(autoResolver());

        // A reverse-proxy prefix is dropped: legacy servers compare against the procedure.
        TokenSource.AuthHeaders headers = ts.getAuthHeaders(resourceServer.url("/proxy" + RPC_PATH).url(), "POST");

        // Legacy keeps the DPoP scheme; only the htu changes.
        assertThat(headers.getAuthHeader()).isEqualTo("DPoP test-token");
        JWTClaimsSet proof = SignedJWT.parse(headers.getDpopHeader()).getJWTClaimsSet();
        assertThat(proof.getStringClaim("htu")).isEqualTo(RPC_PATH);
        assertThat(proof.getStringClaim("htm")).isEqualTo("POST");
        assertThat(proof.getStringClaim("ath")).isNotEmpty();
        // Paths too short to be a procedure keep the full URI.
        URL shortPath = resourceServer.url("/kas").url();
        assertThat(htuOf(ts.getAuthHeaders(shortPath, "POST"))).isEqualTo(shortPath.toString());
        URL trailingSlashes = resourceServer.url("/proxy" + RPC_PATH + "///").url();
        assertThat(htuOf(ts.getAuthHeaders(trailingSlashes, "POST"))).isEqualTo(RPC_PATH);
        // Discovery is unauthenticated and its definitive answer is cached per origin.
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
        RecordedRequest configRequest = discoveryRequests.get(0);
        assertThat(configRequest.getMethod()).isEqualTo("POST");
        assertThat(configRequest.getHeader("Connect-Protocol-Version")).isEqualTo("1");
        assertThat(configRequest.getBody().readUtf8()).isEqualTo("{}");
        assertThat(discoveryRequests.get(1).getMethod()).isEqualTo("GET");
        for (RecordedRequest r : discoveryRequests) {
            assertThat(r.getHeader("Authorization")).isNull();
            assertThat(r.getHeader("DPoP")).isNull();
        }
    }

    @Test
    void advertisedSendsRfc9449Headers() throws Exception {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{" + ALGS + "}}"));
        URL url = resourceServer.url(RPC_PATH + "?q=1").url();

        TokenSource.AuthHeaders headers = tokenSource(autoResolver()).getAuthHeaders(url, "POST");

        assertThat(headers.getAuthHeader()).isEqualTo("DPoP test-token");
        JWTClaimsSet proof = SignedJWT.parse(headers.getDpopHeader()).getJWTClaimsSet();
        assertThat(proof.getStringClaim("htu")).isEqualTo(resourceServer.url(RPC_PATH).toString());
        assertThat(proof.getStringClaim("ath")).isNotEmpty();
    }

    @Test
    void inconclusiveDiscoveryIsLegacyUntilTheRetryInterval() throws Exception {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, new MockResponse().setResponseCode(503));
        TokenSource ts = tokenSource(clockedResolver());

        assertThat(htuOf(ts.getAuthHeaders(rpcUrl(), "POST"))).isEqualTo(RPC_PATH);

        // The 5xx was no answer, so the origin is asked again once the retry interval passes.
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{" + ALGS + "}}"));
        nanos.addAndGet(RETRY_INTERVAL.toNanos() - 1);
        assertThat(htuOf(ts.getAuthHeaders(rpcUrl(), "POST"))).isEqualTo(RPC_PATH);
        nanos.addAndGet(1);
        assertThat(htuOf(ts.getAuthHeaders(rpcUrl(), "POST"))).isEqualTo(rpcUrl().toString());
        assertThat(discoveredPaths()).containsExactly(
                WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH, WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void discoveryFailureStillHonorsProtectedResourceMetadata() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, new MockResponse().setResponseCode(503));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        DPoPModeResolver resolver = autoResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void protectedResourceFailureAfterAWellKnownAnswerIsConclusive() {
        // RFC 9728 is new, so once the well-known configuration has answered, its errors don't matter.
        wellKnown.put(PROTECTED_RESOURCE_PATH, new MockResponse().setResponseCode(503));
        DPoPModeResolver resolver = clockedResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        nanos.addAndGet(RETRY_INTERVAL.toNanos());
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void unreachableServerIsLegacy() throws Exception {
        URL url = resourceServer.url(RPC_PATH).url();
        resourceServer.shutdown();
        assertThat(autoResolver().modeFor(url)).isEqualTo(DPoPMode.LEGACY);
    }

    @Test
    void unparseableDocumentIsDefinitivelyLegacy() {
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("<html>not json</html>"));
        DPoPModeResolver resolver = autoResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void notFoundIsDefinitivelyLegacy() {
        // service v0.11.x: no RFC 9449 advertisement anywhere.
        DPoPModeResolver resolver = autoResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void legacyAnswerExpiresSoAnUpgradedServerIsRediscovered() {
        DPoPModeResolver resolver = clockedResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);

        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{" + ALGS + "}}"));
        nanos.addAndGet(TTL.toNanos() - 1);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);

        nanos.addAndGet(1);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(
                WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH, WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    @Test
    void rfc9449AnswerExpiresSoAReconfiguredServerIsRediscovered() {
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        DPoPModeResolver resolver = clockedResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);

        // E.g. the origin is now fronted by a legacy KAS or a gateway that no longer publishes metadata.
        wellKnown.remove(PROTECTED_RESOURCE_PATH);
        nanos.addAndGet(TTL.toNanos());
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(
                WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH,
                WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void seededAnswerExpires() {
        DPoPModeResolver resolver = clockedResolver();
        resolver.recordRfc9449(resourceServer.url("/").url());
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveryRequests).isEmpty();

        nanos.addAndGet(TTL.toNanos());
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void zeroTtlDisablesTheCache() {
        DPoPModeResolver resolver = new DPoPModeResolver(DPoPMode.AUTO, new OkHttpClient(), Duration.ZERO, nanos::get,
                DPoPModeResolver.DISCOVERY_TIMEOUT);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        resolver.recordRfc9449(resourceServer.url("/").url());
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(
                WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH,
                WELL_KNOWN_CONFIGURATION_PROCEDURE, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void bootstrapAdvertisementSeedsPlatformWithoutDiscovery() {
        Struct algs = Struct.newBuilder().putFields("dpop_signing_alg_values_supported",
                Value.newBuilder().setListValue(ListValue.newBuilder()
                        .addValues(Value.newBuilder().setStringValue("ES256"))).build()).build();
        Struct declined = Struct.newBuilder()
                .putFields("dpop", Value.newBuilder().setStructValue(Struct.newBuilder()
                        .putFields("rfc9449", Value.newBuilder().setBoolValue(false).build())).build())
                .putAllFields(algs.getFieldsMap())
                .build();
        assertThat(DPoPModeResolver.advertisesRfc9449(algs)).isTrue();
        assertThat(DPoPModeResolver.advertisesRfc9449(declined)).isFalse();
        assertThat(DPoPModeResolver.advertisesRfc9449(Struct.getDefaultInstance())).isFalse();

        DPoPModeResolver resolver = autoResolver();
        resolver.recordRfc9449(resourceServer.url("/").url());
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveryRequests).isEmpty();

        DPoPModeResolver legacy = new DPoPModeResolver(DPoPMode.LEGACY, null);
        legacy.recordRfc9449(resourceServer.url("/").url());
        assertThat(legacy.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
    }

    @ParameterizedTest
    @EnumSource(value = DPoPMode.class, names = {"LEGACY", "RFC9449"})
    void overrideSkipsDiscovery(DPoPMode mode) throws Exception {
        // Advertise the opposite of the override to show the override wins.
        if (mode == DPoPMode.LEGACY) {
            wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{" + ALGS + "}}"));
        }
        TokenSource ts = tokenSource(new DPoPModeResolver(mode, new OkHttpClient()));

        TokenSource.AuthHeaders headers = ts.getAuthHeaders(rpcUrl(), "POST");

        assertThat(headers.getAuthHeader()).isEqualTo("DPoP test-token");
        assertThat(htuOf(headers)).isEqualTo(mode == DPoPMode.LEGACY ? RPC_PATH : rpcUrl().toString());
        assertThat(discoveryRequests).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = DPoPMode.class, names = {"LEGACY", "RFC9449"})
    void nonceChallengeIsRetriedInEachMode(DPoPMode expected) throws Exception {
        if (expected == DPoPMode.RFC9449) {
            wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{" + ALGS + "}}"));
        }
        AuthInterceptor interceptor = new AuthInterceptor(tokenSource(autoResolver()));
        OkHttpClient client = new OkHttpClient.Builder().addInterceptor(interceptor.dpopRetryInterceptor()).build();
        challengeNextCall.set(true);

        // Connect-shaped request, so the legacy retry signs the procedure htu.
        Request request = new Request.Builder()
                .url(resourceServer.url("/proxy" + RPC_PATH))
                .header("Connect-Protocol-Version", "1")
                .post(RequestBody.create(new byte[0]))
                .build();
        try (Response response = client.newCall(request).execute()) {
            assertThat(response.code()).isEqualTo(200);
        }

        RecordedRequest retry = lastNonDiscoveryRequest();
        assertThat(retry.getHeader("Authorization")).isEqualTo("DPoP test-token");
        JWTClaimsSet proof = SignedJWT.parse(retry.getHeader("DPoP")).getJWTClaimsSet();
        assertThat(proof.getStringClaim("nonce")).isEqualTo("server-nonce");
        assertThat(proof.getStringClaim("htu")).isEqualTo(expected == DPoPMode.LEGACY
                ? RPC_PATH
                : resourceServer.url("/proxy" + RPC_PATH).toString());
    }

    @Test
    void nonceRetryKeepsTheChallengedProofsForm() throws Exception {
        // The origin now advertises RFC 9449, but the challenged request was signed legacy.
        wellKnown.put(WELL_KNOWN_CONFIGURATION_PROCEDURE, json("{\"configuration\":{" + ALGS + "}}"));
        AuthInterceptor interceptor = new AuthInterceptor(tokenSource(autoResolver()));
        OkHttpClient client = new OkHttpClient.Builder().addInterceptor(interceptor.dpopRetryInterceptor()).build();
        challengeNextCall.set(true);
        URL url = resourceServer.url("/proxy" + RPC_PATH).url();
        TokenSource.AuthHeaders legacy = tokenSource(DPoPModeResolver.fixed(DPoPMode.LEGACY)).getAuthHeaders(url, "POST");

        Request request = new Request.Builder()
                .url(url)
                .header("Authorization", legacy.getAuthHeader())
                .header("DPoP", legacy.getDpopHeader())
                .post(RequestBody.create(new byte[0]))
                .build();
        try (Response response = client.newCall(request).execute()) {
            assertThat(response.code()).isEqualTo(200);
        }

        RecordedRequest retry = lastNonDiscoveryRequest();
        JWTClaimsSet proof = SignedJWT.parse(retry.getHeader("DPoP")).getJWTClaimsSet();
        assertThat(proof.getStringClaim("nonce")).isEqualTo("server-nonce");
        assertThat(proof.getStringClaim("htu")).isEqualTo(RPC_PATH);
        assertThat(discoveryRequests).isEmpty();
    }

    @Test
    void bearerTokenSkipsDiscoveryAndProof() {
        tokenServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return json(BEARER_TOKEN_RESPONSE);
            }
        });
        TokenSource.AuthHeaders headers = tokenSource(autoResolver()).getAuthHeaders(rpcUrl(), "POST");
        assertThat(headers.getAuthHeader()).isEqualTo("Bearer test-token");
        assertThat(headers.getDpopHeader()).isNull();
        assertThat(discoveryRequests).isEmpty();
    }

    @Test
    void autoRequiresHttpClientAndBuilderRejectsNull() {
        assertThatThrownBy(() -> new DPoPModeResolver(DPoPMode.AUTO, null))
                .isInstanceOf(IllegalArgumentException.class);
        SDKBuilder builder = SDKBuilder.newBuilder();
        assertThatThrownBy(() -> builder.dpopMode(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> builder.dpopDiscoveryCacheTtl(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> builder.dpopDiscoveryCacheTtl(Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(builder.dpopDiscoveryCacheTtl(Duration.ZERO)).isSameAs(builder);
    }

    private DPoPModeResolver autoResolver() {
        return new DPoPModeResolver(DPoPMode.AUTO, new OkHttpClient());
    }

    private DPoPModeResolver clockedResolver() {
        return new DPoPModeResolver(DPoPMode.AUTO, new OkHttpClient(), TTL, nanos::get,
                DPoPModeResolver.DISCOVERY_TIMEOUT);
    }

    // Discovers once, then checks the answer is reused until just before ttl and rediscovered at ttl.
    private void assertCachedFor(Duration ttl) {
        DPoPModeResolver resolver = clockedResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        int afterFirst = countConfigRequests();
        nanos.addAndGet(ttl.toNanos() - 1);
        resolver.modeFor(rpcUrl());
        assertThat(countConfigRequests()).isEqualTo(afterFirst);
        nanos.addAndGet(1);
        resolver.modeFor(rpcUrl());
        assertThat(countConfigRequests()).isEqualTo(afterFirst + 1);
    }

    private int countConfigRequests() {
        return (int) discoveredPaths().stream().filter(WELL_KNOWN_CONFIGURATION_PROCEDURE::equals).count();
    }

    private TokenSource tokenSource(DPoPModeResolver resolver) {
        return new TokenSource(
                new ClientSecretBasic(new ClientID("test-client"), new Secret("test-secret")),
                rsaKey,
                JWSAlgorithm.RS256,
                tokenServer.url("/token").uri(),
                new ClientCredentialsGrant(),
                null,
                resolver);
    }

    private static String htuOf(TokenSource.AuthHeaders headers) throws Exception {
        return SignedJWT.parse(headers.getDpopHeader()).getJWTClaimsSet().getStringClaim("htu");
    }

    private URL rpcUrl() {
        return resourceServer.url(RPC_PATH).url();
    }

    private List<String> discoveredPaths() {
        return discoveryRequests.stream().map(RecordedRequest::getPath).collect(java.util.stream.Collectors.toList());
    }

    private RecordedRequest lastNonDiscoveryRequest() throws InterruptedException {
        RecordedRequest last = null;
        for (int i = resourceServer.getRequestCount(); i > 0; i--) {
            RecordedRequest r = resourceServer.takeRequest();
            if (!isDiscovery(r.getPath())) {
                last = r;
            }
        }
        return last;
    }

    private static boolean isDiscovery(String path) {
        return path.startsWith("/.well-known/") || path.equals(WELL_KNOWN_CONFIGURATION_PROCEDURE);
    }

    private static MockResponse json(String body) {
        return new MockResponse().setBody(body).setHeader("Content-Type", "application/json");
    }
}
