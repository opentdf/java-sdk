package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

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
        assertThat(providers)
                .as("No security providers registered")
                .isNotNull()
                .isNotEmpty();
        assertThat(providers[0].getName())
                .as("Expected BCFIPS as the first security provider but got: %s - the java.security.fips.test file was likely not loaded",
                        providers[0].getName())
                .isEqualTo("BCFIPS");
    }

    @Test
    void bcJsseIsRegistered() {
        assertThat(Security.getProvider("BCJSSE"))
                .as("BCJSSE provider is not registered - the java.security.fips.test file was likely not loaded")
                .isNotNull();
    }

    @Test
    void sunJceIsNotRegistered() {
        assertThat(Security.getProvider("SunJCE"))
                .as("SunJCE provider is still registered - it should have been removed by java.security.fips.test")
                .isNull();
    }

    @Test
    void keyManagerFactoryAlgorithmIsPkix() {
        assertThat(Security.getProperty("ssl.KeyManagerFactory.algorithm"))
                .as("ssl.KeyManagerFactory.algorithm was not overridden to PKIX - the java.security.fips.test file was likely not loaded")
                .isEqualTo("PKIX");
    }

    @Test
    void providerResolves() {
        assertThat(HkdfResolver.get())
                .as("the sdk-fips-bc library must be on the path so that the Hkdf provider resolves. this is configured in the surefire plugin and the sdk-fips-bc project must be packaged")
                .isNotNull();
    }
}
