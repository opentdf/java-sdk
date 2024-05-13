package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class PolicyInfo {
    private NanoTDFPolicyType type;
    private boolean hasECDSABinding;
    private byte[] body;
    private byte[] binding;

    public PolicyInfo() {
    }

    public PolicyInfo(byte[] bytes, ECCMode eccMode) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        this.type = NanoTDFPolicyType.values()[buffer.get()];
        this.hasECDSABinding = eccMode.isECDSABindingEnabled();

        if (this.type == NanoTDFPolicyType.REMOTE_POLICY) {
            ResourceLocator policyUrl = new ResourceLocator(bytes);
            this.body = policyUrl.writeIntoBuffer();
        } else {
            int policyLength = buffer.getInt();
            this.body = new byte[policyLength];
            buffer.get(this.body);
        }

        int bindingBytesSize = 16; // GMAC length
        if (this.hasECDSABinding) {
            bindingBytesSize = ECCMode.getECDSASignatureStructSize(eccMode.getEllipticCurveType());
        }

        this.binding = new byte[bindingBytesSize];
        buffer.get(this.binding);
    }
}