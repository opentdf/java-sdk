package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the java.security.fips.test properties file was actually loaded when running
 * under the fips Maven profile. Without this check, a misconfigured argLine would silently run
 * all other tests against the default (non-FIPS) provider stack.
 */
@EnabledIfSystemProperty(named = "org.bouncycastle.fips.approved_only", matches = "true")
class FipsProviderVerificationTest {

    @Test
    void bcFipsIsFirstProvider() {
        var providers = Security.getProviders();
        assertNotNull(providers, "No security providers registered");
        assertTrue(providers.length > 0, "Provider list is empty");
        assertEquals("BCFIPS", providers[0].getName(),
                "Expected BCFIPS as the first security provider but got: " + providers[0].getName()
                + " — the java.security.fips.test file was likely not loaded");
    }

    @Test
    void bcJsseIsRegistered() {
        assertNotNull(Security.getProvider("BCJSSE"),
                "BCJSSE provider is not registered — the java.security.fips.test file was likely not loaded");
    }

    @Test
    void sunJceIsNotRegistered() {
        assertNull(Security.getProvider("SunJCE"),
                "SunJCE provider is still registered — it should have been removed by java.security.fips.test");
    }

    @Test
    void keyManagerFactoryAlgorithmIsPkix() {
        assertEquals("PKIX", Security.getProperty("ssl.KeyManagerFactory.algorithm"),
                "ssl.KeyManagerFactory.algorithm was not overridden to PKIX — the java.security.fips.test file was likely not loaded");
    }
}
