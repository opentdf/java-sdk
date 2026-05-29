package io.opentdf.platform.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Locates {@link HybridKeyWrapProvider} implementations via
 * {@link ServiceLoader} and dispatches on {@link KeyType}. The provider list
 * is loaded once on first access (holder-class idiom) using the resolver's own
 * classloader for deterministic behavior under shaded jars.
 */
final class HybridKeyWrapResolver {

    private HybridKeyWrapResolver() {}

    private static final class Holder {
        static final List<HybridKeyWrapProvider> PROVIDERS = load();

        private static List<HybridKeyWrapProvider> load() {
            List<HybridKeyWrapProvider> out = new ArrayList<>();
            for (HybridKeyWrapProvider p : ServiceLoader.load(
                    HybridKeyWrapProvider.class,
                    HybridKeyWrapResolver.class.getClassLoader())) {
                out.add(p);
            }
            return out;
        }
    }

    /**
     * Return the first registered provider that supports {@code keyType}.
     *
     * @throws SDKException if no provider is registered for the requested type.
     */
    static HybridKeyWrapProvider get(KeyType keyType) {
        for (HybridKeyWrapProvider p : Holder.PROVIDERS) {
            if (p.supports(keyType)) {
                return p;
            }
        }
        throw new SDKException("No HybridKeyWrapProvider registered for " + keyType
                + ". Add io.opentdf.platform:sdk-hybrid-bouncycastle to your classpath.");
    }
}
