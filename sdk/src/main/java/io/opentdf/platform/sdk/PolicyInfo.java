package io.opentdf.platform.sdk;

import java.nio.ByteBuffer;

public class PolicyInfo {
    private static final int DEFAULT_BINDING_SIZE = 8;
    private NanoTDFType.PolicyType type;
    private byte[] body;
    private byte[] binding;

    public PolicyInfo() {
    }

    public PolicyInfo(ByteBuffer buffer, ECCMode eccMode) {
        this.type = NanoTDFType.PolicyType.values()[buffer.get()];

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

            // read short value into int to prevent possible overflow resulting in negative length
            int policyLength = ByteBuffer.wrap(policyLengthBuf).getShort();

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

        this.binding = readBinding(buffer, eccMode);
    }

    static byte[] readBinding(ByteBuffer buffer, ECCMode eccMode) {
        byte[] binding;
        if (eccMode.isECDSABindingEnabled()) { // ECDSA - The size of binding depends on the curve.
            int rSize = getSize(buffer.get(), eccMode.getCurve());
            // don't bother to validate since we can only create an array of size 1024 bytes
            byte[] rBytes = new byte[rSize];
            buffer.get(rBytes);
            int sSize = getSize(buffer.get(), eccMode.getCurve());
            byte[] sBytes = new byte[sSize];
            buffer.get(sBytes);
            binding = new byte[rSize + sSize + 2];
            System.arraycopy(new byte[]{(byte) rSize}, 0, binding, 0, 1);
            System.arraycopy(rBytes, 0, binding, 1, rSize);
            System.arraycopy(new byte[]{(byte) sSize}, 0, binding, 1 + rSize, 1);
            System.arraycopy(sBytes, 0, binding, 2 + rSize, sSize);
        } else {
            binding = new byte[DEFAULT_BINDING_SIZE];
            buffer.get(binding);
        }

        return binding;
    }

    private static int getSize(byte size, NanoTDFType.ECCurve curve) {
        int elementSize = Byte.toUnsignedInt(size);
        if (elementSize > curve.getKeySize()) {
            throw new SDK.MalformedTDFException(
                    String.format("Invalid ECDSA binding size. Expected signature components to be at most %d bytes but got (%d) bytes for curve %s.",
                            curve.getKeySize(), elementSize, curve.getCurveName()));
        }
        return elementSize;
    }

    public int getTotalSize() {

        int totalSize = 0;

        if (this.type == NanoTDFType.PolicyType.REMOTE_POLICY) {
            totalSize = (1 + body.length + binding.length);
        } else {
            if (type == NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT ||
                    type == NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED) {

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
            // 1 - resource locator
            // 2 - ephemeral public key, the size depends on ECC mode.

            // Write the length of the policy

            short policyLength = (short) body.length;
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