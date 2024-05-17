package io.opentdf.platform.sdk.nanotdf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

class SymmetricAndPayloadConfigTest {
    private SymmetricAndPayloadConfig config;

    @BeforeEach
    void setUp() {
        config = new SymmetricAndPayloadConfig();
    }

    @Test
    void settingAndGettingSignatureFlag() {
        config.setHasSignature(true);
        assertTrue(config.hasSignature());
        config.setHasSignature(false);
        assertFalse(config.hasSignature());
    }

    @Test
    void settingAndGettingSignatureECCMode() {
        for (EllipticCurve curve : EllipticCurve.values()) {
            if (curve != EllipticCurve.SECP256K1) { // SDK doesn't support 'secp256k1' curve
                config.setSignatureECCMode(curve);
                assertEquals(curve, config.getSignatureECCMode());
            }
        }
    }

    @Test
    void settingUnsupportedSignatureECCMode() {
        assertThrows(RuntimeException.class, () -> config.setSignatureECCMode(EllipticCurve.SECP256K1));
    }

    @Test
    void settingAndGettingCipherType() {
        for (NanoTDFCipher cipher : NanoTDFCipher.values()) {
            config.setSymmetricCipherType(cipher);
            assertEquals(cipher, config.getCipherType());
        }
    }

    @Test
    void gettingSymmetricAndPayloadConfigAsByte() {
        config.setHasSignature(true);
        config.setSignatureECCMode(EllipticCurve.SECP256R1);
        config.setSymmetricCipherType(NanoTDFCipher.AES_256_GCM_64_TAG);
        byte expected = (byte) (1 << 7 | 0x00 << 4 | 0x00);
        assertEquals(expected, config.getSymmetricAndPayloadConfigAsByte());
    }
}