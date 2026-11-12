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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.opentdf.platform.sdk.DPoPModeResolver.OPENTDF_CONFIGURATION_PATH;
import static io.opentdf.platform.sdk.DPoPModeResolver.PROTECTED_RESOURCE_PATH;
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
                if (path.startsWith("/.well-known/")) {
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
    void wellKnownDpopBlockOnly() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{\"dpop\":{\"rfc9449\":true}}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH);
    }

    @Test
    void wellKnownDpopBlockOverridesTopLevelAlgs() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH,
                json("{\"configuration\":{\"dpop\":{\"rfc9449\":false}," + ALGS + "}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
    }

    @Test
    void wellKnownTopLevelAlgsOnly() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{\"platform_issuer\":\"x\"," + ALGS + "}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH);
    }

    @Test
    void wellKnownEmptyAlgsIsNotAnAdvertisement() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH,
                json("{\"configuration\":{\"dpop_signing_alg_values_supported\":[]}}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void protectedResourceMetadataOnly() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{\"platform_issuer\":\"x\"}}"));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{\"resource\":\"x\"," + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void protectedResourceMetadataWithoutOpentdfConfiguration() throws Exception {
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
    }

    @Test
    void bothAdvertisedStopsAtWellKnown() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{\"dpop\":{\"rfc9449\":true}," + ALGS + "}}"));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        assertThat(autoResolver().modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH);
    }

    @Test
    void neitherAdvertisedSendsLegacyHeaders() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{\"platform_issuer\":\"x\"}}"));
        TokenSource ts = tokenSource(autoResolver());

        // A reverse-proxy prefix is dropped: legacy servers compare against the procedure.
        TokenSource.AuthHeaders headers = ts.getAuthHeaders(resourceServer.url("/proxy" + RPC_PATH).url(), "POST");

        // Legacy keeps the DPoP scheme; only the htu changes.
        assertThat(headers.getAuthHeader()).isEqualTo("DPoP test-token");
        JWTClaimsSet proof = SignedJWT.parse(headers.getDpopHeader()).getJWTClaimsSet();
        assertThat(proof.getStringClaim("htu")).isEqualTo(RPC_PATH);
        assertThat(proof.getStringClaim("htm")).isEqualTo("POST");
        assertThat(proof.getStringClaim("ath")).isNotEmpty();
        // Non-RPC requests, and paths too short to be a procedure, keep the full URI.
        URL plain = resourceServer.url("/kas/v2/rewrap").url();
        assertThat(htuOf(ts.getAuthHeaders(plain, "POST", null, false))).isEqualTo(plain.toString());
        URL shortPath = resourceServer.url("/kas").url();
        assertThat(htuOf(ts.getAuthHeaders(shortPath, "POST"))).isEqualTo(shortPath.toString());
        // Discovery is unauthenticated and its definitive answer is cached per origin.
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH);
        for (RecordedRequest r : discoveryRequests) {
            assertThat(r.getMethod()).isEqualTo("GET");
            assertThat(r.getHeader("Authorization")).isNull();
            assertThat(r.getHeader("DPoP")).isNull();
        }
    }

    @Test
    void advertisedSendsRfc9449Headers() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{" + ALGS + "}}"));
        URL url = resourceServer.url(RPC_PATH + "?q=1").url();

        TokenSource.AuthHeaders headers = tokenSource(autoResolver()).getAuthHeaders(url, "POST");

        assertThat(headers.getAuthHeader()).isEqualTo("DPoP test-token");
        JWTClaimsSet proof = SignedJWT.parse(headers.getDpopHeader()).getJWTClaimsSet();
        assertThat(proof.getStringClaim("htu")).isEqualTo(resourceServer.url(RPC_PATH).toString());
        assertThat(proof.getStringClaim("ath")).isNotEmpty();
    }

    @Test
    void discoveryFailureIsLegacyForThatRequestOnly() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, new MockResponse().setResponseCode(503));
        TokenSource ts = tokenSource(autoResolver());

        assertThat(htuOf(ts.getAuthHeaders(rpcUrl(), "POST"))).isEqualTo(RPC_PATH);

        // The 5xx was transient, so the next request discovers again and now sees RFC 9449.
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{" + ALGS + "}}"));
        assertThat(htuOf(ts.getAuthHeaders(rpcUrl(), "POST"))).isEqualTo(rpcUrl().toString());
        assertThat(discoveredPaths()).containsExactly(
                OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH, OPENTDF_CONFIGURATION_PATH);
    }

    @Test
    void discoveryFailureStillHonorsProtectedResourceMetadata() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, new MockResponse().setResponseCode(503));
        wellKnown.put(PROTECTED_RESOURCE_PATH, json("{" + ALGS + "}"));
        DPoPModeResolver resolver = autoResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.RFC9449);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void unreachableServerIsLegacy() throws Exception {
        URL url = resourceServer.url(RPC_PATH).url();
        resourceServer.shutdown();
        assertThat(autoResolver().modeFor(url)).isEqualTo(DPoPMode.LEGACY);
    }

    @Test
    void unparseableDocumentIsDefinitivelyLegacy() throws Exception {
        wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("<html>not json</html>"));
        DPoPModeResolver resolver = autoResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void notFoundIsDefinitivelyLegacy() throws Exception {
        // service v0.11.x: no RFC 9449 advertisement anywhere.
        DPoPModeResolver resolver = autoResolver();
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(resolver.modeFor(rpcUrl())).isEqualTo(DPoPMode.LEGACY);
        assertThat(discoveredPaths()).containsExactly(OPENTDF_CONFIGURATION_PATH, PROTECTED_RESOURCE_PATH);
    }

    @Test
    void bootstrapAdvertisementSeedsPlatformWithoutDiscovery() throws Exception {
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
            wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{" + ALGS + "}}"));
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
            wellKnown.put(OPENTDF_CONFIGURATION_PATH, json("{\"configuration\":{" + ALGS + "}}"));
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
    void bearerTokenSkipsDiscoveryAndProof() throws Exception {
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
        assertThatThrownBy(() -> SDKBuilder.newBuilder().dpopMode(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private DPoPModeResolver autoResolver() {
        return new DPoPModeResolver(DPoPMode.AUTO, new OkHttpClient());
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
            if (!r.getPath().startsWith("/.well-known/")) {
                last = r;
            }
        }
        return last;
    }

    private static MockResponse json(String body) {
        return new MockResponse().setBody(body).setHeader("Content-Type", "application/json");
    }
}
