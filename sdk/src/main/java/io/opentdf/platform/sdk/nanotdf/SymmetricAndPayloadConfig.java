package io.opentdf.platform.sdk.nanotdf;

public class SymmetricAndPayloadConfig {
    private NanoTDFCipher cipher;
    private int payloadSize;

    public SymmetricAndPayloadConfig() {
    }

    public SymmetricAndPayloadConfig(byte configByte) {
        this.cipher = NanoTDFCipher.values()[(configByte & 0xF0) >> 4];
        this.payloadSize = configByte & 0x0F;
    }

    public NanoTDFCipher getCipher() {
        return this.cipher;
    }

    public void setCipher(NanoTDFCipher cipher) {
        this.cipher = cipher;
    }

    public int getPayloadSize() {
        return this.payloadSize;
    }

    public void setPayloadSize(int payloadSize) {
        this.payloadSize = payloadSize;
    }

    public byte toByte() {
        return (byte) ((this.cipher.ordinal() << 4) | this.payloadSize);
    }
}