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
            int policyUrlSize = policyUrl.getTotalSize();
            body = new byte[policyUrlSize];
            buffer = ByteBuffer.wrap(body);
            policyUrl.writeIntoBuffer(buffer);
            bytes = Arrays.copyOfRange(bytes, policyUrlSize, bytes.length);
        } else {
            int policyLength = buffer.getInt();

            if (this.type == NanoTDFPolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    this.type == NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED) {

                // Copy the policy data.
                this.body = new byte[policyLength];
                buffer.get(this.body);

                bytes = Arrays.copyOfRange(bytes, policyLength, bytes.length);

            } else if (this.type == NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS) {
                throw new RuntimeException("Embedded policy with key access is not supported.");
            } else {
                throw new RuntimeException("Invalid policy type.");
            }
        }

        int bindingBytesSize = 8; // GMAC length
        if(this.hasECDSABinding) { // ECDSA - The size of binding depends on the curve.
            bindingBytesSize = ECCMode.getECDSASignatureStructSize(eccMode.getEllipticCurveType());
        }

        this.binding = new byte[bindingBytesSize];
        buffer.get(this.binding);
    }

    public int getTotalSize() {

        int totalSize = 0;

        if (type == NanoTDFPolicyType.REMOTE_POLICY) {
            totalSize = (1 + body.length + binding.length);
        } else {
            if (type == NanoTDFPolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    type == NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED) {

                int policySize =  body.length;
                totalSize = (1 + Integer.BYTES + body.length + binding.length);
            } else {
                throw new RuntimeException("Embedded policy with key access is not supported.");
            }
        }
        return totalSize;
    }

    public int writeIntoBuffer(ByteBuffer buffer) {

        if (buffer.remaining() < getTotalSize()) {
            throw new RuntimeException("Failed to write policy info - invalid buffer size.");
        }

        if (binding.length == 0) {
            throw new RuntimeException("Policy binding is not set");
        }

        int totalBytesWritten = 0;

        // Write the policy info type.
        buffer.put((byte) type.ordinal());
        totalBytesWritten += 1; // size of byte

        // Remote policy - The body is resource locator.
        if (type == NanoTDFPolicyType.REMOTE_POLICY) {

            // Write the policy in this case it's a resource locator;
            buffer.put(body);
            totalBytesWritten += body.length;

        } else { // Embedded Policy

            // Embedded policy layout
            // 1 - Length of the policy;
            // 2 - policy bytes itself
            // 3 - policy key access( ONLY for EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS)
            //      1 - resource locator
            //      2 - ephemeral public key, the size depends on ECC mode.

            // Write the length of the policy
            buffer.putInt(body.length);
            totalBytesWritten += Integer.BYTES;

            if (type == NanoTDFPolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    type == NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED) {

                int policySize = body.length;

                // Copy the policy data.
                buffer.put(body);
                totalBytesWritten += policySize;
            } else if (type == NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS) {
                throw new RuntimeException("Embedded policy with key access is not supported.");
            } else {
                throw new RuntimeException("Invalid policy type.");
            }
        }

        // Write the binding.
        buffer.put(binding);
        totalBytesWritten += binding.length;

        return totalBytesWritten;
    }
}