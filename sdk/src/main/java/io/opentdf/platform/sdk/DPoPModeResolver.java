package io.opentdf.platform.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Decides, per server origin, whether DPoP proofs for resource requests use the RFC 9449 htu or
 * the legacy htu older platforms expect (see {@link DPoPMode}). In {@link DPoPMode#AUTO} the
 * server's advertisement is fetched per origin and cached for {@link #DEFAULT_CACHE_TTL}, since
 * the KAS, gateway, and IdP in front of an origin can change independently of a long-lived
 * client. A discovery that got no answer from the server falls back to legacy for that request
 * only and is retried next time. Mirrors
 * the Go SDK's {@code sdk/auth/dpop_mode.go}. It is thread-safe.
 */
class DPoPModeResolver {
    static final String OPENTDF_CONFIGURATION_PATH = "/.well-known/opentdf-configuration";
    static final String PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
    private static final String DPOP_ALGS_KEY = "dpop_signing_alg_values_supported";
    private static final long MAX_DOCUMENT_BYTES = 1 << 20;
    static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(5);

    private static final Logger logger = LoggerFactory.getLogger(DPoPModeResolver.class);

    private final DPoPMode configured;
    @Nullable
    private final OkHttpClient httpClient;
    private final long cacheTtlNanos;
    private final LongSupplier nanoClock;
    // Definitive answers only (never AUTO), keyed by origin (scheme://host:port)
    private final Map<String, CachedMode> modeByOrigin = new ConcurrentHashMap<>();

    private static final class CachedMode {
        final DPoPMode mode;
        final long expiresAtNanos;

        CachedMode(DPoPMode mode, long expiresAtNanos) {
            this.mode = mode;
            this.expiresAtNanos = expiresAtNanos;
        }
    }

    /**
     * @param configured the requested mode; anything other than AUTO is used as-is
     * @param httpClient client used for discovery. It must not carry the SDK's auth
     *                   interceptors: discovery requests are sent without Authorization or DPoP.
     *                   May be null when {@code configured} is not AUTO.
     */
    DPoPModeResolver(DPoPMode configured, @Nullable OkHttpClient httpClient) {
        this(configured, httpClient, DEFAULT_CACHE_TTL, System::nanoTime);
    }

    /** As above, with the cache lifetime and clock exposed for tests. */
    DPoPModeResolver(DPoPMode configured, @Nullable OkHttpClient httpClient, Duration cacheTtl,
                     LongSupplier nanoClock) {
        this.configured = Objects.requireNonNull(configured, "configured");
        if (configured == DPoPMode.AUTO && httpClient == null) {
            throw new IllegalArgumentException("DPoP mode discovery requires an HTTP client");
        }
        this.httpClient = httpClient;
        this.cacheTtlNanos = cacheTtl.toNanos();
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
    }

    static DPoPModeResolver fixed(DPoPMode mode) {
        if (mode == DPoPMode.AUTO) {
            throw new IllegalArgumentException("a fixed DPoP mode cannot be AUTO");
        }
        return new DPoPModeResolver(mode, null);
    }

    /**
     * Whether an opentdf well-known configuration advertises RFC 9449. A {@code dpop} block, when
     * present, is authoritative; otherwise a non-empty {@code dpop_signing_alg_values_supported}
     * means support, since every release that publishes it (service v0.18.0+) accepts a full-URL htu.
     */
    static boolean advertisesRfc9449(JsonObject config) {
        JsonElement dpop = config.get("dpop");
        if (dpop != null && dpop.isJsonObject()) {
            JsonElement rfc9449 = dpop.getAsJsonObject().get("rfc9449");
            return rfc9449 != null && rfc9449.isJsonPrimitive() && rfc9449.getAsJsonPrimitive().isBoolean()
                    && rfc9449.getAsBoolean();
        }
        return hasNonEmptyArray(config, DPOP_ALGS_KEY);
    }

    /** As {@link #advertisesRfc9449(JsonObject)}, for the configuration the SDK bootstraps from. */
    static boolean advertisesRfc9449(Struct config) {
        Value dpop = config.getFieldsOrDefault("dpop", null);
        if (dpop != null && dpop.hasStructValue()) {
            Value rfc9449 = dpop.getStructValue().getFieldsOrDefault("rfc9449", null);
            return rfc9449 != null && rfc9449.hasBoolValue() && rfc9449.getBoolValue();
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
            cache(TokenSource.getOrigin(url), DPoPMode.RFC9449);
        }
    }

    /** @return {@link DPoPMode#RFC9449} or {@link DPoPMode#LEGACY} for the URL's origin. */
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
        // Discovery runs outside any lock, so concurrent requests for an uncached or expired origin
        // may each discover; the last definitive answer is kept.
        DPoPMode discovered = discover(origin);
        if (discovered == null) {
            return DPoPMode.LEGACY;
        }
        cache(origin, discovered);
        return discovered;
    }

    private void cache(String origin, DPoPMode mode) {
        modeByOrigin.put(origin, new CachedMode(mode, nanoClock.getAsLong() + cacheTtlNanos));
    }

    /** @return the definitive mode, or null when the server gave no answer (don't cache). */
    @Nullable
    private DPoPMode discover(String origin) {
        // 1 + 2: the opentdf configuration. The HTTP form wraps it in "configuration".
        Exception wellKnownError = null;
        try {
            JsonObject wellKnown = fetchJson(origin + OPENTDF_CONFIGURATION_PATH);
            if (wellKnown != null) {
                JsonElement configuration = wellKnown.get("configuration");
                JsonObject config = configuration != null && configuration.isJsonObject()
                        ? configuration.getAsJsonObject()
                        : wellKnown;
                if (advertisesRfc9449(config)) {
                    return logResolved(origin, DPoPMode.RFC9449, "opentdf-configuration");
                }
            }
        } catch (IOException e) {
            wellKnownError = e;
        }

        // 3: RFC 9728 protected resource metadata. It is new, so its absence says little.
        Exception resourceError = null;
        try {
            JsonObject resourceMetadata = fetchJson(origin + PROTECTED_RESOURCE_PATH);
            if (resourceMetadata != null && hasNonEmptyArray(resourceMetadata, DPOP_ALGS_KEY)) {
                return logResolved(origin, DPoPMode.RFC9449, "oauth-protected-resource");
            }
        } catch (IOException e) {
            resourceError = e;
        }

        if (wellKnownError != null || resourceError != null) {
            if (logger.isWarnEnabled()) {
                logger.warn("DPoP server discovery failed for {}; using legacy proofs for this request"
                                + " (well-known error: {}, protected-resource error: {})",
                        origin, String.valueOf(wellKnownError), String.valueOf(resourceError));
            }
            return null;
        }
        return logResolved(origin, DPoPMode.LEGACY, "no RFC 9449 advertisement");
    }

    /**
     * GET a well-known document without credentials.
     *
     * @return the JSON object, or null for a definitive "not published" (a non-5xx error status
     *         or a 200 whose body is not a JSON object)
     * @throws IOException on a network error or a 5xx, which are transient
     */
    @Nullable
    private JsonObject fetchJson(String url) throws IOException {
        Request request = new Request.Builder().url(url).get().header("Accept", "application/json").build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (response.code() >= 500) {
                throw new IOException("GET " + url + " returned HTTP " + response.code());
            }
            if (response.code() != 200) {
                logger.debug("GET {} returned HTTP {}; treating as not advertised", url, response.code());
                return null;
            }
            // A truncated document fails to parse below, which is treated as not advertised.
            String text = response.peekBody(MAX_DOCUMENT_BYTES).string();
            try {
                return JsonParser.parseString(text).getAsJsonObject();
            } catch (JsonParseException | IllegalStateException e) {
                logger.debug("GET {} did not return a JSON object; treating as not advertised", url, e);
                return null;
            }
        }
    }

    private static boolean hasNonEmptyArray(JsonObject object, String key) {
        JsonElement value = object.get(key);
        return value != null && value.isJsonArray() && value.getAsJsonArray().size() > 0;
    }

    private static DPoPMode logResolved(String origin, DPoPMode mode, String reason) {
        logger.debug("DPoP style for {} is {} ({})", origin, mode, reason);
        return mode;
    }
}
