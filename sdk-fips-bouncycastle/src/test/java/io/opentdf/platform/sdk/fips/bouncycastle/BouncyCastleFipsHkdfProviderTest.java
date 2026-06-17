package io.opentdf.platform.sdk.fips.bouncycastle;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

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
    void computeHKDF_nullSaltMatchesEmptySalt() {
        byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);

        byte[] withNull = provider.computeHKDF(null, secret);
        byte[] withEmpty = provider.computeHKDF(new byte[0], secret);

        assertThat(withNull).isEqualTo(withEmpty);
    }

    @Test
    void computeHKDF_nullSaltMatchesZeroSalt() {
        byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);

        byte[] withNull = provider.computeHKDF(null, secret);
        byte[] withZero = provider.computeHKDF(new byte[32], secret);

        assertThat(withNull).isEqualTo(withZero);
    }

    @Test
    void computeHKDF_throwsOnNullSecret() {
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);

        assertThatNullPointerException()
                .isThrownBy(() -> provider.computeHKDF(salt, null))
                .withMessage("secret must not be null");
    }
}
