package io.opentdf.platform.sdk.spi;

import io.opentdf.platform.sdk.KeyType;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KemProviderTest {

    /** A provider written against the SPI before generateKeyPair existed: it implements only the original methods. */
    private static final class WrapOnlyProvider implements KemProvider {
        @Override
        public Set<KeyType> supportedKeyTypes() {
            return EnumSet.of(KeyType.MLKEM768Key);
        }

        @Override
        public byte[] wrapDEK(KeyType keyType, String publicKeyPEM, byte[] dek) {
            return dek;
        }

        @Override
        public byte[] unwrapDEK(KeyType keyType, String privateKeyPEM, byte[] wrapped) {
            return wrapped;
        }
    }

    @Test
    void generateKeyPairDefaultsToUnsupported() {
        assertThatThrownBy(() -> new WrapOnlyProvider().generateKeyPair(KeyType.MLKEM768Key))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining(WrapOnlyProvider.class.getName())
                .hasMessageContaining(KeyType.MLKEM768Key.toString());
    }
}
