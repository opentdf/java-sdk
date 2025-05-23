package io.opentdf.platform.sdk;

public class NanoTDFType {
    public enum ECCurve {
        SECP256R1("secp256r1"),
        SECP384R1("secp384r1"),
        SECP521R1("secp384r1"),
        SECP256K1("secp256k1");

        private final String name;

        ECCurve(String curveName) {
            this.name = curveName;
        }

        @Override
        public String toString() {
            return name;
        }
    }
    // ResourceLocator Protocol
    public enum Protocol {
        HTTP,
        HTTPS
    }
    // ResourceLocator Identifier
    public enum IdentifierType {
        NONE(0),
        TWO_BYTES(2),
        EIGHT_BYTES(8),
        THIRTY_TWO_BYTES(32);
        private final int length;
        IdentifierType(int length) {
            this.length = length;
        }
        public int getLength() {
            return length;
        }
    }

    public enum PolicyType {
        REMOTE_POLICY,
        EMBEDDED_POLICY_PLAIN_TEXT,
        EMBEDDED_POLICY_ENCRYPTED,
        EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS
    }

    public enum Cipher {
        AES_256_GCM_64_TAG ,
        AES_256_GCM_96_TAG ,
        AES_256_GCM_104_TAG ,
        AES_256_GCM_112_TAG ,
        AES_256_GCM_120_TAG ,
        AES_256_GCM_128_TAG ,
        EAD_AES_256_HMAC_SHA_256
    }
}
