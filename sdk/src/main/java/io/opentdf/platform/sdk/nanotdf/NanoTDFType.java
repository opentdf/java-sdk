package io.opentdf.platform.sdk.nanotdf;

public class NanoTDFType {
    public enum ECCurve {
        SECP256R1("secp256r1"),
        SECP384R1("secp384r1"),
        SECP521R1("secp384r1"),
        SECP256K1("secp256k1");

        private String name;

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
//        NoIdentifier            protocolHeader = 0 << 4
//        TwoByteIdentifier       protocolHeader = 1 << 4
//        EightByteIdentifier     protocolHeader = 2 << 4
//        ThirtyTwoByteIdentifier protocolHeader = 3 << 4
        NONE,
        TWO_BYTES,
        EIGHT_BYTES,
        THIRTY_TWO_BYTES
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
