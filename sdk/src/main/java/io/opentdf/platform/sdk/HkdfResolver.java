package io.opentdf.platform.sdk;

import java.util.ServiceLoader;

/**
 * Locates a registered {@link HkdfProvider} via {@link ServiceLoader}.
 * Returns {@code null} when no provider is registered, signalling
 * the caller to use the JDK-native fallback.
 */
final class HkdfResolver {

    private HkdfResolver() {}

    private static final class Holder {
        static final HkdfProvider PROVIDER = load();

        private static HkdfProvider load() {
            return ServiceLoader.load(HkdfProvider.class, HkdfResolver.class.getClassLoader())
                    .findFirst()
                    .orElse(null);
        }
    }

    static HkdfProvider get() {
        return Holder.PROVIDER;
    }
}
