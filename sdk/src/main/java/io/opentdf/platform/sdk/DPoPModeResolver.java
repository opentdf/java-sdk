package io.opentdf.platform.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.BufferedSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Decides, per server origin, whether DPoP proofs for resource requests use the RFC 9449 htu or
 * the legacy htu older platforms expect (see {@link DPoPMode}). Follows the same rules as the Go
 * SDK's {@code sdk/auth/dpop_mode.go}. It is thread-safe.
 *
 * <p>In {@link DPoPMode#AUTO} an origin's answer is cached for a TTL (default
 * {@link #DEFAULT_CACHE_TTL}; zero disables the cache), since the KAS, gateway, and IdP in front of
 * an origin can change independently of a long-lived client. A discovery that got no usable answer
 * from the well-known configuration (and no RFC 9728 advertisement) falls back to legacy for
 * {@link #RETRY_INTERVAL} before the origin is asked again. Concurrent requests to an origin share
 * one discovery, which runs off the caller's thread so a cancelled caller doesn't abort it.
 */
class DPoPModeResolver {
    static final String WELL_KNOWN_CONFIGURATION_PROCEDURE =
            "/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration";
    static final String PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
    static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(5);
    static final Duration RETRY_INTERVAL = Duration.ofSeconds(30);
    static final Duration DISCOVERY_TIMEOUT = Duration.ofSeconds(10);
    private static final String DPOP_ALGS_KEY = "dpop_signing_alg_values_supported";
    private static final long MAX_DOCUMENT_BYTES = 1 << 20;
    private static final MediaType JSON = MediaType.get("application/json");

    private static final Logger logger = LoggerFactory.getLogger(DPoPModeResolver.class);

    private final DPoPMode configured;
    @Nullable
    private final OkHttpClient discoveryClient;
    private final long cacheTtlNanos;
    private final long discoveryTimeoutNanos;
    private final LongSupplier nanoClock;
    // Resolved answers only (never AUTO), keyed by origin (scheme://host:port)
    private final Map<String, CachedMode> modeByOrigin = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<DPoPMode>> discoveries = new ConcurrentHashMap<>();

    private static final class CachedMode {
        final DPoPMode mode;
        final long expiresAtNanos;

        CachedMode(DPoPMode mode, long expiresAtNanos) {
            this.mode = mode;
            this.expiresAtNanos = expiresAtNanos;
        }
    }

    /** The outcome of asking an origin whether it accepts RFC 9449 proofs. */
    private static final class Discovery {
        final DPoPMode mode;
        // False when the well-known configuration got no usable answer and RFC 9728 metadata did
        // not advertise support, so the legacy fallback is only kept for RETRY_INTERVAL.
        final boolean conclusive;
        @Nullable
        final IOException wellKnownError;
        @Nullable
        final IOException resourceError;

        Discovery(DPoPMode mode, boolean conclusive, @Nullable IOException wellKnownError,
                  @Nullable IOException resourceError) {
            this.mode = mode;
            this.conclusive = conclusive;
            this.wellKnownError = wellKnownError;
            this.resourceError = resourceError;
        }
    }

    /**
     * @param configured the requested mode; anything other than AUTO is used as-is
     * @param httpClient client used for discovery. It must not carry the SDK's auth
     *                   interceptors: discovery requests are sent without Authorization or DPoP.
     *                   May be null when {@code configured} is not AUTO.
     */
    DPoPModeResolver(DPoPMode configured, @Nullable OkHttpClient httpClient) {
        this(configured, httpClient, DEFAULT_CACHE_TTL, System::nanoTime, DISCOVERY_TIMEOUT);
    }

    /**
     * As above, with a cache lifetime ({@link Duration#ZERO} disables caching), the clock that
     * ages cache entries, and the time limit for one discovery.
     */
    DPoPModeResolver(DPoPMode configured, @Nullable OkHttpClient httpClient, Duration cacheTtl,
                     LongSupplier nanoClock, Duration discoveryTimeout) {
        this.configured = Objects.requireNonNull(configured, "configured");
        if (configured == DPoPMode.AUTO && httpClient == null) {
            throw new IllegalArgumentException("DPoP mode discovery requires an HTTP client");
        }
        // A redirect is not the origin's own answer.
        this.discoveryClient = httpClient == null ? null
                : httpClient.newBuilder().followRedirects(false).followSslRedirects(false).build();
        this.cacheTtlNanos = cacheTtl.toNanos();
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
        this.discoveryTimeoutNanos = discoveryTimeout.toNanos();
    }

    static DPoPModeResolver fixed(DPoPMode mode) {
        if (mode == DPoPMode.AUTO) {
            throw new IllegalArgumentException("a fixed DPoP mode cannot be AUTO");
        }
        return new DPoPModeResolver(mode, null);
    }

    /**
     * Whether an opentdf well-known configuration advertises RFC 9449. A {@code dpop} block with a
     * boolean {@code rfc9449} decides the answer; otherwise a non-empty
     * {@code dpop_signing_alg_values_supported} means support, since every release that publishes
     * it (service v0.18.0+) accepts a full-URL htu. A false result does not rule out support
     * advertised through RFC 9728 metadata.
     */
    static boolean advertisesRfc9449(JsonObject config) {
        JsonElement dpop = config.get("dpop");
        if (dpop != null && dpop.isJsonObject()) {
            JsonElement rfc9449 = dpop.getAsJsonObject().get("rfc9449");
            if (rfc9449 != null && rfc9449.isJsonPrimitive() && rfc9449.getAsJsonPrimitive().isBoolean()) {
                return rfc9449.getAsBoolean();
            }
        }
        return hasNonEmptyArray(config, DPOP_ALGS_KEY);
    }

    /** As {@link #advertisesRfc9449(JsonObject)}, for the configuration the SDK bootstraps from. */
    static boolean advertisesRfc9449(Struct config) {
        Value dpop = config.getFieldsOrDefault("dpop", null);
        if (dpop != null && dpop.hasStructValue()) {
            Value rfc9449 = dpop.getStructValue().getFieldsOrDefault("rfc9449", null);
            if (rfc9449 != null && rfc9449.hasBoolValue()) {
                return rfc9449.getBoolValue();
            }
        }
        Value algs = config.getFieldsOrDefault(DPOP_ALGS_KEY, null);
        return algs != null && algs.hasListValue() && algs.getListValue().getValuesCount() > 0;
    }

    /**
     * Record that the server at {@code url} accepts RFC 9449, e.g. from the well-known
     * configuration the SDK already fetched. Only positives are seeded: a server that omits the
     * well-known advertisement may still publish RFC 9728 metadata.
     */
    void recordRfc9449(URL url) {
        if (configured == DPoPMode.AUTO) {
            cache(TokenSource.getOrigin(url), DPoPMode.RFC9449, cacheTtlNanos);
        }
    }

    /**
     * @return {@link DPoPMode#RFC9449} or {@link DPoPMode#LEGACY} for the URL's origin. In AUTO this
     *         may block on discovery, which is bounded by the discovery timeout.
     * @throws SDKException if the thread is interrupted while waiting for discovery
     */
    DPoPMode modeFor(URL url) {
        if (configured != DPoPMode.AUTO) {
            return configured;
        }
        String origin = TokenSource.getOrigin(url);
        CachedMode known = modeByOrigin.get(origin);
        // Compare by difference: nanoTime values may wrap.
        if (known != null && nanoClock.getAsLong() - known.expiresAtNanos < 0) {
            return known.mode;
        }

        CompletableFuture<DPoPMode> pending = new CompletableFuture<>();
        CompletableFuture<DPoPMode> shared = discoveries.putIfAbsent(origin, pending);
        if (shared == null) {
            shared = pending;
            try {
                discoveryClient.dispatcher().executorService().execute(() -> discoverAndCache(origin, pending));
            } catch (RejectedExecutionException e) {
                // The client is shutting down; discover on this thread instead.
                discoverAndCache(origin, pending);
            }
        }
        try {
            return shared.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SDKException("interrupted while discovering the DPoP style of " + origin, e);
        } catch (ExecutionException e) {
            throw new SDKException("DPoP style discovery failed for " + origin, e);
        }
    }

    private void discoverAndCache(String origin, CompletableFuture<DPoPMode> result) {
        try {
            Discovery d = discover(origin);
            cache(origin, d.mode, d.conclusive ? cacheTtlNanos
                    : Math.min(RETRY_INTERVAL.toNanos(), cacheTtlNanos));
            if (logger.isDebugEnabled()) {
                logger.debug("discovered DPoP htu form for {}: {} (conclusive={}, well-known error={},"
                                + " protected-resource error={})",
                        origin, d.mode, d.conclusive, d.wellKnownError, d.resourceError);
            }
            result.complete(d.mode);
        } catch (RuntimeException e) {
            result.completeExceptionally(e);
        } finally {
            discoveries.remove(origin, result);
        }
    }

    private void cache(String origin, DPoPMode mode, long ttlNanos) {
        modeByOrigin.put(origin, new CachedMode(mode, nanoClock.getAsLong() + ttlNanos));
    }

    /**
     * Ask the server at {@code origin} whether it accepts RFC 9449 proofs: the opentdf well-known
     * configuration, then RFC 9728 metadata if that doesn't advertise support. Neither request
     * carries credentials or a proof: a client can't authenticate in a DPoP form it hasn't chosen.
     */
    private Discovery discover(String origin) {
        long deadline = System.nanoTime() + discoveryTimeoutNanos;

        IOException wellKnownError = null;
        try {
            Request request = new Request.Builder()
                    .url(origin + WELL_KNOWN_CONFIGURATION_PROCEDURE)
                    .post(RequestBody.create("{}", JSON))
                    .header("Connect-Protocol-Version", "1")
                    .build();
            JsonObject wellKnown = fetchJson(request, deadline);
            if (wellKnown != null) {
                JsonElement configuration = wellKnown.get("configuration");
                if (configuration != null && configuration.isJsonObject()
                        && advertisesRfc9449(configuration.getAsJsonObject())) {
                    return new Discovery(DPoPMode.RFC9449, true, null, null);
                }
            }
        } catch (IOException e) {
            wellKnownError = e;
        }

        IOException resourceError = null;
        try {
            JsonObject metadata = fetchJson(
                    new Request.Builder().url(origin + PROTECTED_RESOURCE_PATH).get().build(), deadline);
            if (metadata != null && hasNonEmptyArray(metadata, DPOP_ALGS_KEY)) {
                return new Discovery(DPoPMode.RFC9449, true, wellKnownError, null);
            }
        } catch (IOException e) {
            resourceError = e;
        }

        // RFC 9728 is new, so its absence says little. Only conclude "legacy" once the well-known
        // configuration itself has answered.
        return new Discovery(DPoPMode.LEGACY, wellKnownError == null, wellKnownError, resourceError);
    }

    /**
     * Send a discovery request.
     *
     * @return the JSON object, or null when the server definitively serves no such document: HTTP
     *         404, 405 or 501, or a 200 whose body isn't a JSON object (e.g. a catch-all page)
     * @throws IOException when the server gave no usable answer: a network error, timeout,
     *         redirect, a body over 1 MiB, or any other status (e.g. a gateway's 401 or 429, or a 5xx)
     */
    @Nullable
    private JsonObject fetchJson(Request request, long deadline) throws IOException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new IOException("DPoP discovery timed out before " + request.url());
        }
        Call call = discoveryClient.newCall(request.newBuilder().header("Accept", "application/json").build());
        call.timeout().timeout(remaining, TimeUnit.NANOSECONDS);
        try (Response response = call.execute()) {
            int code = response.code();
            if (code == 404 || code == 405 || code == 501) {
                return null;
            }
            if (code != 200) {
                throw new IOException(request.method() + " " + request.url() + " returned HTTP " + code);
            }
            ResponseBody body = response.body();
            if (body == null) {
                throw new IOException(request.method() + " " + request.url() + " returned no body");
            }
            BufferedSource source = body.source();
            if (source.request(MAX_DOCUMENT_BYTES + 1)) {
                throw new IOException(request.method() + " " + request.url() + " returned over "
                        + MAX_DOCUMENT_BYTES + " bytes");
            }
            try {
                return JsonParser.parseString(source.readUtf8()).getAsJsonObject();
            } catch (JsonParseException | IllegalStateException e) {
                return null;
            }
        }
    }

    private static boolean hasNonEmptyArray(JsonObject object, String key) {
        JsonElement value = object.get(key);
        return value != null && value.isJsonArray() && value.getAsJsonArray().size() > 0;
    }
}
