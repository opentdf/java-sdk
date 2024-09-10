package io.opentdf.platform.sdk.nanotdf;

public class ECCMode {
    private ECCModeStruct data;

    public ECCMode() {
        data = new ECCModeStruct();
        data.curveMode = 0x00; // SECP256R1
        data.unused = 0; // fill with zero(unused)
        data.useECDSABinding = 0; // enable ECDSA binding
    }

    public ECCMode(byte value) {
        data = new ECCModeStruct();
        int curveMode = value & 0x07; // first 3 bits
        setEllipticCurve(NanoTDFType.ECCurve.values()[curveMode]);
        int useECDSABinding = (value >> 7) & 0x01; // most significant bit
        data.useECDSABinding = useECDSABinding;
    }

    public void setECDSABinding(boolean flag) {
        if (flag) {
            data.useECDSABinding = 1;
        } else {
            data.useECDSABinding = 0;
        }
    }

    public void setEllipticCurve(NanoTDFType.ECCurve curve) {
        switch (curve) {
            case SECP256R1:
                data.curveMode = 0x00;
                break;
            case SECP384R1:
                data.curveMode = 0x01;
                break;
            case SECP521R1:
                data.curveMode = 0x02;
                break;
            case SECP256K1:
                throw new RuntimeException("SDK doesn't support 'secp256k1' curve");
            default:
                throw new RuntimeException("Unsupported ECC algorithm.");
        }
    }

    public NanoTDFType.ECCurve getEllipticCurveType() {
        return NanoTDFType.ECCurve.values()[data.curveMode];
    }

    public boolean isECDSABindingEnabled() {
        return data.useECDSABinding == 1;
    }

    public String getCurveName() {
        return getEllipticCurveName(NanoTDFType.ECCurve.values()[data.curveMode]);
    }

    public byte getECCModeAsByte() {
        int value = (data.useECDSABinding << 7) | data.curveMode;
        return (byte) value;
    }

    public static String getEllipticCurveName(NanoTDFType.ECCurve curve) {
        switch (curve) {
            case SECP256R1:
                return "secp256r1";
            case SECP384R1:
                return "secp384r1";
            case SECP521R1:
                return "secp521r1";
            case SECP256K1:
                throw new RuntimeException("SDK doesn't support 'secp256k1' curve");
            default:
                throw new RuntimeException("Unsupported ECC algorithm.");
        }
    }

    public static int getECKeySize(NanoTDFType.ECCurve curve) {
        switch (curve) {
            case SECP256K1:
                throw new RuntimeException("SDK doesn't support 'secp256k1' curve");
            case SECP256R1:
                return 32;
            case SECP384R1:
                return 48;
            case SECP521R1:
                return 66;
            default:
                throw new RuntimeException("Unsupported ECC algorithm.");
        }
    }

    public static int getECDSASignatureStructSize(NanoTDFType.ECCurve curve) {
        int keySize = getECKeySize(curve);
        return (1 + keySize + 1 + keySize);
    }

    public static int getECKeySize(String curveName) {
        return ECKeyPair.getECKeySize(curveName);
    }

    public static int getECCompressedPubKeySize(NanoTDFType.ECCurve curve) {
        switch (curve) {
            case SECP256K1:
                throw new RuntimeException("SDK doesn't support 'secp256k1' curve");
            case SECP256R1:
                return 33;
            case SECP384R1:
                return 49;
            case SECP521R1:
                return 67;
            default:
                throw new RuntimeException("Unsupported ECC algorithm.");
        }
    }

    private class ECCModeStruct {
        int curveMode;
        int unused;
        int useECDSABinding;
    }
}