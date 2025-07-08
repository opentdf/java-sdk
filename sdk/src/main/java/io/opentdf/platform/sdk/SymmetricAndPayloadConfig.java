package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Key;

public class SymmetricAndPayloadConfig {
    private Data data;

    public SymmetricAndPayloadConfig() {
        data = new Data();
        data.symmetricCipherEnum = 0x0; // AES_256_GCM_64_TAG
        data.signatureECCMode = 0x00; // SECP256R1
        data.hasSignature = 1;
    }

    public SymmetricAndPayloadConfig(byte value) {
        data = new Data();

        int cipherType = value & 0x0F; // first 4 bits
        setSymmetricCipherType(NanoTDFType.Cipher.values()[cipherType]);

        int signatureECCMode = (value >> 4) & 0x07;
        data.signatureECCMode = signatureECCMode;

        int hasSignature = (value >> 7) & 0x01; // most significant bit
        data.hasSignature = hasSignature;
    }

    public void setHasSignature(boolean flag) {
        data.hasSignature = flag ? 1 : 0;
    }

    public void setSignatureECCMode(NanoTDFType.ECCurve eccCurve) {
        if (!eccCurve.isSupported) {
            throw new RuntimeException(String.format("Unsupported ECC algorithm: %s", eccCurve.curveName));
        }
        data.signatureECCMode = eccCurve.curveMode;
    }

    public void setSymmetricCipherType(NanoTDFType.Cipher cipherType) {
        switch (cipherType) {
            case AES_256_GCM_64_TAG:
                data.symmetricCipherEnum = 0x00;
                break;
            case AES_256_GCM_96_TAG:
                data.symmetricCipherEnum = 0x01;
                break;
            case AES_256_GCM_104_TAG:
                data.symmetricCipherEnum = 0x02;
                break;
            case AES_256_GCM_112_TAG:
                data.symmetricCipherEnum = 0x03;
                break;
            case AES_256_GCM_120_TAG:
                data.symmetricCipherEnum = 0x04;
                break;
            case AES_256_GCM_128_TAG:
                data.symmetricCipherEnum = 0x05;
                break;
            case EAD_AES_256_HMAC_SHA_256:
                data.symmetricCipherEnum = 0x06;
                break;
            default:
                throw new RuntimeException("Unsupported symmetric cipher for signature.");
        }
    }

    public boolean hasSignature() {
        return data.hasSignature == 1;
    }

    public NanoTDFType.Cipher getCipherType() {
        return NanoTDFType.Cipher.values()[data.symmetricCipherEnum];
    }

    public byte getSymmetricAndPayloadConfigAsByte() {
        int value = data.hasSignature << 7 | data.signatureECCMode << 4 | data.symmetricCipherEnum;
        return (byte) value;
    }

    static public int sizeOfAuthTagForCipher(NanoTDFType.Cipher cipherType) {
        switch (cipherType) {
            case AES_256_GCM_64_TAG:
                return 8;
            case AES_256_GCM_96_TAG:
                return 12;
            case AES_256_GCM_104_TAG:
                return 13;
            case AES_256_GCM_112_TAG:
                return 14;
            case AES_256_GCM_120_TAG:
                return 15;
            case AES_256_GCM_128_TAG:
                return 16;
            case EAD_AES_256_HMAC_SHA_256:
                return 32;
            default:
                throw new IllegalArgumentException("Unsupported symmetric cipher for signature.");
        }
    }

    public NanoTDFType.ECCurve getSignatureECCMode() {
        return NanoTDFType.ECCurve.fromCurveMode(this.data.signatureECCMode);
    }

    private static class Data {
        int symmetricCipherEnum;
        int signatureECCMode;
        int hasSignature;
    }
}