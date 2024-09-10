package io.opentdf.platform.sdk.nanotdf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

class HeaderTest {
    private Header header;

    @BeforeEach
    void setUp() {
        header = new Header();
    }

    @Test
    void settingAndGettingMagicNumberAndVersion() {
        byte[] expected = header.getMagicNumberAndVersion();
        assertArrayEquals(expected, new byte[]{0x4C, 0x31, 0x4C});
    }

    @Test
    void settingAndGettingKasLocator() {
        ResourceLocator locator = new ResourceLocator("http://test.com");
        header.setKasLocator(locator);
        assertEquals(locator, header.getKasLocator());
    }

    @Test
    void settingAndGettingECCMode() {
        ECCMode mode = new ECCMode((byte) 1);
        header.setECCMode(mode);
        assertEquals(mode, header.getECCMode());
    }

    @Test
    void settingAndGettingPayloadConfig() {
        SymmetricAndPayloadConfig config = new SymmetricAndPayloadConfig((byte) 1);
        header.setPayloadConfig(config);
        assertEquals(config, header.getPayloadConfig());
    }

    @Test
    void settingAndGettingEphemeralKey() {
        ECCMode mode = new ECCMode((byte) 1); // Initialize the ECCMode object
        header.setECCMode(mode); // Set the ECCMode object

        int keySize = mode.getECCompressedPubKeySize(mode.getEllipticCurveType());
        byte[] key = new byte[keySize]; // Ensure the key size is correct
        header.setEphemeralKey(key);
        assertArrayEquals(key, header.getEphemeralKey());
    }

    @Test
    void settingEphemeralKeyWithInvalidSize() {
        byte[] key = new byte[]{1, 2, 3};
        header.setECCMode(new ECCMode((byte) 1)); // ECC mode with key size > 3
        assertThrows(IllegalArgumentException.class, () -> header.setEphemeralKey(key));
    }

    @Test
    void writingIntoBufferWithInsufficientSize() {
        ByteBuffer buffer = ByteBuffer.allocate(1); // Buffer with insufficient size
        assertThrows(NullPointerException.class, () -> header.writeIntoBuffer(buffer));
    }
}