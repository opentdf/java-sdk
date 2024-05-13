package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Header {
    private static final byte[] MAGIC_NUMBER_AND_VERSION = new byte[]{0x4E, 0x54, 0x44};
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

    public void setPolicyInfo(PolicyInfo policyInfo) {
        this.policyInfo = policyInfo;
    }
}