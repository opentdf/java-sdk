package io.opentdf.platform.sdk;

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
        setEllipticCurve(NanoTDFType.ECCurve.fromCurveMode(curveMode));
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

    public boolean isECDSABindingEnabled() {
        return data.useECDSABinding == 1;
    }

    public byte getECCModeAsByte() {
        int value = (data.useECDSABinding << 7) | data.curveMode;
        return (byte) value;
    }

    public static int getECDSASignatureStructSize(NanoTDFType.ECCurve curve) {
        int keySize = curve.getKeySize();
        return (1 + keySize + 1 + keySize);
    }

    public NanoTDFType.ECCurve getCurve() {
        return NanoTDFType.ECCurve.fromCurveMode(data.curveMode);
    }

    private class ECCModeStruct {
        int curveMode;
        int unused;
        int useECDSABinding;
    }
}