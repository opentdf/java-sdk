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
        byte[] remainingBytes = new byte[buffer.remaining()];
        buffer.get(remainingBytes);

        if (this.type == NanoTDFPolicyType.REMOTE_POLICY) {
            ResourceLocator policyUrl = new ResourceLocator(remainingBytes);
            int policyUrlSize = policyUrl.getTotalSize();
            this.body = new byte[policyUrlSize];
            buffer = ByteBuffer.wrap(this.body);
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
        System.arraycopy(bytes, 0, this.binding, 0, bindingBytesSize);
    }

    public int getTotalSize() {

        int totalSize = 0;

        if (this.type == NanoTDFPolicyType.REMOTE_POLICY) {
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

    public NanoTDFPolicyType getPolicyType() {
        return this.type;
    }

    public void setRemotePolicy(String policyUrl) {
        ResourceLocator remotePolicyUrl = new ResourceLocator(policyUrl);
        int size = remotePolicyUrl.getTotalSize();
        this.body = new byte[size];
        remotePolicyUrl.writeIntoBuffer(ByteBuffer.wrap(this.body));
        this.type = NanoTDFPolicyType.REMOTE_POLICY;
    }

    public String getRemotePolicyUrl() {
        if (this.type != NanoTDFPolicyType.REMOTE_POLICY) {
            throw new RuntimeException("Policy is not remote type.");
        }
        ResourceLocator policyUrl = new ResourceLocator(this.body);
        return policyUrl.getResourceUrl();
    }

    public void setEmbeddedPlainTextPolicy(byte[] bytes) {
        this.body = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.body, 0, bytes.length);
        this.type = NanoTDFPolicyType.EMBEDDED_POLICY_PLAIN_TEXT;
    }

    public byte[] getEmbeddedPlainTextPolicy() {
        if (this.type != NanoTDFPolicyType.EMBEDDED_POLICY_PLAIN_TEXT) {
            throw new RuntimeException("Policy is not embedded plain text type.");
        }
        return this.body;
    }

    public void setEmbeddedEncryptedTextPolicy(byte[] bytes) {
        this.body = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.body, 0, bytes.length);
        this.type = NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED;
    }

    public byte[] getEmbeddedEncryptedTextPolicy() {
        if (this.type != NanoTDFPolicyType.EMBEDDED_POLICY_ENCRYPTED) {
            throw new RuntimeException("Policy is not embedded encrypted text type.");
        }
        return this.body;
    }

    public void setPolicyBinding(byte[] bytes) {
        this.binding = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.binding, 0, bytes.length);
    }

    public byte[] getPolicyBinding() {
        return this.binding;
    }
}