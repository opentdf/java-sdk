package io.opentdf.platform.sdk.spi;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the FIPS-deployment failure mode: when the optional
 * {@code sdk-pqc-bc} module is NOT on the classpath, a request for any
 * hybrid PQC {@link KeyType} must fail with a clean {@link SDKException}
 * that points the user at the missing module — never a
 * {@link NoClassDefFoundError} or a generic NPE.
 *
 * <p>This test lives in the core {@code sdk} module; {@code sdk} does not
 * depend on {@code sdk-pqc-bc}, so the test JVM's classpath naturally lacks
 * any {@link KemProvider} service file. That faithfully simulates the
 * FIPS deployment shape (where {@code sdk-pqc-bc} is intentionally omitted
 * because BouncyCastle's regular jar would collide with {@code bc-fips}).
 *
 * <p>Runs in both the {@code fips} and {@code non-fips} CI legs of
 * {@code .github/workflows/checks.yaml::mavenverify} — same outcome in both,
 * because the behaviour under test is purely classpath-driven.
 */
class KemProvidersTest {

    @ParameterizedTest
    @EnumSource(
            value = KeyType.class,
            names = {
                    "HybridXWingKey",
                    "HybridSecp256r1MLKEM768Key",
                    "HybridSecp384r1MLKEM1024Key"
            })
    void hybridKeyTypeThrowsActionableErrorWhenNoProviderRegistered(KeyType keyType) {
        // The error message embeds keyType.toString() (the algorithm string, e.g. "hpqt:xwing"),
        // not the Java enum name — that's what users see when configuring an algorithm.
        assertThatThrownBy(() -> KemProviders.get(keyType))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining(keyType.toString())
                .hasMessageContaining("sdk-pqc-bc");
    }

    @Test
    void findReturnsEmptyWhenNoProviderRegistered() {
        assertFalse(KemProviders.find(KeyType.HybridXWingKey).isPresent());
    }

    @Test
    void registeredIsEmptyWhenNoProviderOnClasspath() {
        assertTrue(KemProviders.registered().isEmpty(),
                "no KemProvider should be registered in sdk's standalone test classpath; "
                        + "if this fails, the test classpath has been polluted with sdk-pqc-bc "
                        + "and the FIPS-deployment scenario is no longer being verified");
    }
}
