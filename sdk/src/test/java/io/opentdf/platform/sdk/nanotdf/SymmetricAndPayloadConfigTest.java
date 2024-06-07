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
        for (NanoTDFType.ECCurve curve : NanoTDFType.ECCurve.values()) {
            if (curve != NanoTDFType.ECCurve.SECP256K1) { // SDK doesn't support 'secp256k1' curve
                config.setSignatureECCMode(curve);
                assertEquals(curve, config.getSignatureECCMode());
            }
        }
    }

    @Test
    void settingUnsupportedSignatureECCMode() {
        assertThrows(RuntimeException.class, () -> config.setSignatureECCMode(NanoTDFType.ECCurve.SECP256K1));
    }

    @Test
    void settingAndGettingCipherType() {
        for (NanoTDFType.Cipher cipher : NanoTDFType.Cipher.values()) {
            config.setSymmetricCipherType(cipher);
            assertEquals(cipher, config.getCipherType());
        }
    }

    @Test
    void gettingSymmetricAndPayloadConfigAsByte() {
        config.setHasSignature(true);
        config.setSignatureECCMode(NanoTDFType.ECCurve.SECP256R1);
        config.setSymmetricCipherType(NanoTDFType.Cipher.AES_256_GCM_64_TAG);
        byte expected = (byte) (1 << 7 | 0x00 << 4 | 0x00);
        assertEquals(expected, config.getSymmetricAndPayloadConfigAsByte());
    }
}