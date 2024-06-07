package io.opentdf.platform.sdk.nanotdf;

import io.opentdf.platform.sdk.NanoTDF;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class PolicyInfo {
    private NanoTDFType.PolicyType type;
    private boolean hasECDSABinding;
    private byte[] body;
    private byte[] binding;

    public PolicyInfo() {
    }

    public PolicyInfo(ByteBuffer buffer, ECCMode eccMode)  {
        this.type = NanoTDFType.PolicyType.values()[buffer.get()];
        this.hasECDSABinding = eccMode.isECDSABindingEnabled();

        if (this.type == NanoTDFType.PolicyType.REMOTE_POLICY) {

            byte[] oneByte = new byte[1];
            buffer.get(oneByte);

            ResourceLocator policyUrl = new ResourceLocator(ByteBuffer.wrap(oneByte));
            int policyUrlSize = policyUrl.getTotalSize();
            this.body = new byte[policyUrlSize];
            buffer = ByteBuffer.wrap(this.body);
            policyUrl.writeIntoBuffer(buffer);
        } else {
            byte[] policyLengthBuf = new byte[Short.BYTES];
            buffer.get(policyLengthBuf);

            short policyLength = ByteBuffer.wrap(policyLengthBuf).getShort();

            if (this.type == NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    this.type == NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED) {

                // Copy the policy data.
                this.body = new byte[policyLength];
                buffer.get(this.body);
            } else if (this.type == NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS) {
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

        if (this.type == NanoTDFType.PolicyType.REMOTE_POLICY) {
            totalSize = (1 + body.length + binding.length);
        } else {
            if (type == NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    type == NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED) {

                int policySize =  body.length;
                totalSize = (1 + Short.BYTES + body.length + binding.length);
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
        if (type == NanoTDFType.PolicyType.REMOTE_POLICY) {
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


            short policyLength = (short)body.length;
            buffer.putShort(policyLength);
            totalBytesWritten += Short.BYTES;

            if (type == NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    type == NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED) {

                // Copy the policy data.
                buffer.put(body);
                totalBytesWritten += policyLength;
            } else if (type == NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS) {
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

    public NanoTDFType.PolicyType getPolicyType() {
        return this.type;
    }

    public void setRemotePolicy(String policyUrl) {
        ResourceLocator remotePolicyUrl = new ResourceLocator(policyUrl);
        int size = remotePolicyUrl.getTotalSize();
        this.body = new byte[size];
        remotePolicyUrl.writeIntoBuffer(ByteBuffer.wrap(this.body));
        this.type = NanoTDFType.PolicyType.REMOTE_POLICY;
    }

    public String getRemotePolicyUrl() {
        if (this.type != NanoTDFType.PolicyType.REMOTE_POLICY) {
            throw new RuntimeException("Policy is not remote type.");
        }
        ResourceLocator policyUrl = new ResourceLocator(ByteBuffer.wrap(this.body));
        return policyUrl.getResourceUrl();
    }

    public void setEmbeddedPlainTextPolicy(byte[] bytes) {
        this.body = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.body, 0, bytes.length);
        this.type = NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT;
    }

    public byte[] getEmbeddedPlainTextPolicy() {
        if (this.type != NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT) {
            throw new RuntimeException("Policy is not embedded plain text type.");
        }
        return this.body;
    }

    public void setEmbeddedEncryptedTextPolicy(byte[] bytes) {
        this.body = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.body, 0, bytes.length);
        this.type = NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED;
    }

    public byte[] getEmbeddedEncryptedTextPolicy() {
        if (this.type != NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED) {
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