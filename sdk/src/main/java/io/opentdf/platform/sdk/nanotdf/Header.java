package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Header {
    private static final byte[] MAGIC_NUMBER_AND_VERSION = new byte[]{0x4C, 0x31, 0x4C};
    private ResourceLocator kasLocator;
    private ECCMode eccMode;
    private SymmetricAndPayloadConfig payloadConfig;
    private PolicyInfo policyInfo;
    private byte[] ephemeralKey;

    public Header() {
    }

    public Header(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        byte[] magicNumberAndVersion = new byte[3];
        buffer.get(magicNumberAndVersion);
        if (!Arrays.equals(magicNumberAndVersion, MAGIC_NUMBER_AND_VERSION)) {
            throw new RuntimeException("Invalid magic number and version in nano tdf.");
        }

        this.kasLocator = new ResourceLocator(bytes);
        this.eccMode = new ECCMode(buffer.get());
        this.payloadConfig = new SymmetricAndPayloadConfig(buffer.get());
        this.policyInfo = new PolicyInfo(bytes, this.eccMode);

        int compressedPubKeySize = ECCMode.getECCompressedPubKeySize(this.eccMode.getEllipticCurveType());
        this.ephemeralKey = new byte[compressedPubKeySize];
        buffer.get(this.ephemeralKey);
    }

    public byte[] getMagicNumberAndVersion() {
        return Arrays.copyOf(MAGIC_NUMBER_AND_VERSION,  MAGIC_NUMBER_AND_VERSION.length);
    }

    public void setKasLocator(ResourceLocator kasLocator) {
        this.kasLocator = kasLocator;
    }

    public ResourceLocator getKasLocator() {
        return kasLocator;
    }

    public void setECCMode(ECCMode eccMode) {
        this.eccMode = eccMode;
    }

    public ECCMode getECCMode() {
        return eccMode;
    }

    public void setPayloadConfig(SymmetricAndPayloadConfig payloadConfig) {
        this.payloadConfig = payloadConfig;
    }

    public SymmetricAndPayloadConfig getPayloadConfig() {
        return payloadConfig;
    }

    public void setPolicyInfo(PolicyInfo policyInfo) {
        this.policyInfo = policyInfo;
    }

    public PolicyInfo getPolicyInfo() {
        return policyInfo;
    }

    public void setEphemeralKey(byte[] bytes) {
        if (bytes.length < eccMode.getECCompressedPubKeySize(eccMode.getEllipticCurveType())) {
            throw new IllegalArgumentException("Failed to read ephemeral key - invalid buffer size.");
        }
        ephemeralKey = Arrays.copyOf(bytes, eccMode.getECCompressedPubKeySize(eccMode.getEllipticCurveType()));
    }

    public byte[] getEphemeralKey() {
        return Arrays.copyOf(ephemeralKey, ephemeralKey.length);
    }

    public int getTotalSize() {
        int totalSize = 0;
        totalSize += MAGIC_NUMBER_AND_VERSION.length;
        totalSize += kasLocator.getTotalSize();
        totalSize += 1; // size of ECC mode
        totalSize += 1; // size of payload config
        totalSize += policyInfo.getTotalSize();
        totalSize += ephemeralKey.length;
        return totalSize;
    }

    public int writeIntoBuffer(ByteBuffer buffer) {
        if (buffer.remaining() < getTotalSize()) {
            throw new IllegalArgumentException("Failed to write header - invalid buffer size.");
        }

        int totalBytesWritten = 0;
        buffer.put(MAGIC_NUMBER_AND_VERSION);
        totalBytesWritten += MAGIC_NUMBER_AND_VERSION.length;

        int kasLocatorSize = kasLocator.writeIntoBuffer(buffer);
        totalBytesWritten += kasLocatorSize;

        buffer.put(eccMode.getECCModeAsByte());
        totalBytesWritten += 1;

        buffer.put(payloadConfig.getSymmetricAndPayloadConfigAsByte());
        totalBytesWritten += 1;

        int policyInfoSize = policyInfo.writeIntoBuffer(buffer);
        totalBytesWritten += policyInfoSize;

        buffer.put(ephemeralKey);
        totalBytesWritten += ephemeralKey.length;

        return totalBytesWritten;
    }
}