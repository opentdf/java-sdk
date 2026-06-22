package io.opentdf.platform.sdk.spi;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Registry of {@link KemProvider}s discovered via {@link ServiceLoader}.
 *
 * <p>On first access, scans the classpath for
 * {@code META-INF/services/io.opentdf.platform.sdk.spi.KemProvider} entries
 * and builds an unmodifiable {@code KeyType → KemProvider} map. If multiple
 * providers claim the same {@link KeyType}, the first one discovered wins
 * (deterministic per classpath order) and a warning is logged.
 *
 * <p>{@link #get(KeyType)} throws {@link SDKException} with a clear message
 * directing the user to add the relevant provider module (typically
 * {@code sdk-pqc-bc}) when no provider is registered for the requested
 * {@link KeyType}. This is the FIPS-safe failure mode: no
 * {@code NoClassDefFoundError}, no startup-time linkage to BouncyCastle.
 */
public final class KemProviders {

    private static final Logger logger = LoggerFactory.getLogger(KemProviders.class);

    private KemProviders() {}

    /**
     * Initialization-on-demand holder. The JVM guarantees this class is loaded
     * lazily on first access to {@link Holder#CACHE} and that the load happens
     * under the class-init lock — no {@code volatile}, no synchronized block,
     * and no SonarCloud java:S3077 (volatile-Map) warning.
     */
    private static final class Holder {
        static final Map<KeyType, KemProvider> CACHE = load();
    }

    /**
     * @return the provider registered for {@code keyType}.
     * @throws SDKException if no provider is registered. The message tells the user how to fix it.
     */
    public static KemProvider get(KeyType keyType) {
        KemProvider p = Holder.CACHE.get(keyType);
        if (p == null) {
            // The FIPS qualifier is in the message unconditionally so a FIPS-mode user
            // can't follow the "add sdk-pqc-bc" advice into the bcprov/bc-fips namespace
            // collision the optional-module architecture is designed to avoid.
            throw new SDKException("no KemProvider registered for " + keyType
                    + " — add sdk-pqc-bc (or another KemProvider module) to the classpath. "
                    + "Note: hybrid PQC is not available under the fips Maven profile because "
                    + "sdk-pqc-bc's BouncyCastle dependency collides with bc-fips on the same "
                    + "package namespace; the fips build deliberately excludes sdk-pqc-bc.");
        }
        return p;
    }

    /** Non-throwing variant; returns empty when no provider matches. */
    public static Optional<KemProvider> find(KeyType keyType) {
        return Optional.ofNullable(Holder.CACHE.get(keyType));
    }

    /** Set of {@link KeyType}s for which at least one provider is registered. Useful for diagnostics. */
    public static Set<KeyType> registered() {
        return Holder.CACHE.keySet();
    }

    private static Map<KeyType, KemProvider> load() {
        Map<KeyType, KemProvider> map = new HashMap<>();
        for (KemProvider provider : ServiceLoader.load(KemProvider.class)) {
            for (KeyType kt : provider.supportedKeyTypes()) {
                KemProvider existing = map.putIfAbsent(kt, provider);
                if (existing != null && existing != provider) {
                    logger.warn("multiple KemProviders claim {}: keeping {}, ignoring {}",
                            kt, existing.getClass().getName(), provider.getClass().getName());
                }
            }
        }
        return Collections.unmodifiableMap(map);
    }
}
