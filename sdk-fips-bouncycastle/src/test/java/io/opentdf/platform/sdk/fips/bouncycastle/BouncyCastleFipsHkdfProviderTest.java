package io.opentdf.platform.sdk.fips.bouncycastle;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class BouncyCastleFipsHkdfProviderTest {

    private final BouncyCastleFipsHkdfProvider provider = new BouncyCastleFipsHkdfProvider();

    @Test
    void computeHKDF_returns32Bytes() {
        byte[] salt = "test-salt".getBytes(StandardCharsets.UTF_8);
        byte[] secret = "test-secret".getBytes(StandardCharsets.UTF_8);

        byte[] result = provider.computeHKDF(salt, secret);

        assertThat(result).hasSize(32);
    }

    @Test
    void computeHKDF_isDeterministic() {
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);

        byte[] first = provider.computeHKDF(salt, secret);
        byte[] second = provider.computeHKDF(salt, secret);

        assertThat(first).isEqualTo(second);
    }

    @Test
    void computeHKDF_matchesJdkFallback() {
        byte[] salt = "ECKeysSalt".getBytes(StandardCharsets.UTF_8);
        byte[] secret = new byte[32]; // simulated shared secret

        byte[] fipsResult = provider.computeHKDF(salt, secret);
        byte[] jdkResult = io.opentdf.platform.sdk.ECKeyPair.calculateHKDF(salt, secret);

        assertThat(fipsResult).isEqualTo(jdkResult);
    }
}
