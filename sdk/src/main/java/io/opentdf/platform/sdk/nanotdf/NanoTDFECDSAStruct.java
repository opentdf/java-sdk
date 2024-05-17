package io.opentdf.platform.sdk.nanotdf;

public class NanoTDFECDSAStruct {

    public static class IncorrectNanoTDFECDSASignatureSize extends Exception {
        public IncorrectNanoTDFECDSASignatureSize(String errorMessage) {
            super(errorMessage);
        }
    }

    final int[] array = new int[3];

    private final byte[] rLength = new byte[1];
    private byte[] rValue;
    private final byte[] sLength = new byte[1];
    private byte[] sValue;

    NanoTDFECDSAStruct(byte[] ecdsaSignatureValue, int keySize) throws IncorrectNanoTDFECDSASignatureSize {
        if (ecdsaSignatureValue.length != (2 * keySize) + 2) {
            throw new IncorrectNanoTDFECDSASignatureSize("Invalid signature buffer size");
        }

        // Copy value of rLength to signature struct
        int index = 0;
        System.arraycopy(ecdsaSignatureValue, index , this.rLength, 0, 1);

        // Copy the contents of rValue to signature struct
        index += 1;
        int rlen = this.rLength[0];
        this.rValue = new byte[keySize];
        System.arraycopy(ecdsaSignatureValue, index, this.rValue, 0, rlen);

        // Copy value of sLength to signature struct
        index += keySize;
        System.arraycopy(ecdsaSignatureValue, index , this.sLength, 0, 1);

        // Copy value of sValue
        index += 1;
        int slen = this.sLength[0];
        this.sValue = new byte[keySize];
        System.arraycopy(ecdsaSignatureValue, index , this.sValue, 0, slen);
    }

    public byte[] asBytes() {
        byte[] signature = new byte[this.rLength[0] + this.rValue.length + this.sLength[0] + this.sValue.length];

        // Copy value of rLength
        int index = 0;
        System.arraycopy(this.rLength, 0, signature, index, this.rLength.length);

        // Copy the contents of rValue
        index += this.rLength.length;
        System.arraycopy(this.rValue, 0, signature, index, this.rValue.length);

        // Copy value of sLength
        index += this.rValue.length;
        System.arraycopy(this.sLength, 0, signature, index, this.sLength.length);

        // Copy value of sValue
        index += this.sLength.length;
        System.arraycopy(this.sValue, 0, signature, index, this.sValue.length);

        return signature;
    }

    public byte[] getsValue() {
        return sValue;
    }

    public void setsValue(byte[] sValue) {
        this.sValue = sValue;
    }

    public byte getsLength() {
        return sLength[0];
    }

    public void setsLength(byte sLength) {
        this.sLength[0] = sLength;
    }

    public byte[] getrValue() {
        return rValue;
    }

    public void setrValue(byte[] rValue) {
        this.rValue = rValue;
    }

    public byte getrLength() {
        return rLength[0];
    }

    public void setrLength(byte rLength) {
        this.rLength[0] = rLength;
    }
}
