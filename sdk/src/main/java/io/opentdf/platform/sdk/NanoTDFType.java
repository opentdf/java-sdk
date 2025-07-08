package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class NanoTDFType {
    private static final Logger log = LoggerFactory.getLogger(NanoTDFType.class);
    enum ECCurve {
        SECP256R1("secp256r1", 32, 33, 0x00),
        SECP384R1("secp384r1", 48, 49, 0x01),
        SECP521R1("secp521r1", 66, 67, 0x02),
        SECP256K1("secp256k1",-1, -1, -1, false); // Note: SECP256K1 is not supported by the SDK

        final int curveMode;
        final int keySize;
        final int compressedPubKeySize;
        final String curveName;
        final boolean isSupported;


        ECCurve(String curveName, int compressedPubKeySize, int keySize, int curveMode) {
            this(curveName, compressedPubKeySize, keySize, curveMode, true);
        }

        ECCurve(String curveName, int compressedPubKeySize, int keySize, int curveMode, boolean isSupported) {
            this.compressedPubKeySize = compressedPubKeySize;
            this.keySize = keySize;
            this.curveMode = curveMode;
            this.curveName = curveName ;
            this.isSupported = isSupported;
        }

        static ECCurve fromCurveMode(int curveMode) {
            for (ECCurve curve : ECCurve.values()) {
                if (curve.curveMode == curveMode) {
                    return curve;
                }
            }
            throw new IllegalArgumentException("No enum constant for curve mode: " + curveMode);
        }

        public static ECCurve fromAlgorithm(String algorithm) {
            if (algorithm == null) {
                log.warn("got a null algorithm, returning SECP256R1 as default");
                return SECP256R1;
            }

            assert algorithm.startsWith("ec:");
            var searchKey = algorithm.substring("ec:".length());
            return Arrays.stream(ECCurve.values())
                    .filter(v -> v.curveName.equalsIgnoreCase(searchKey))
                    .findAny()
                    .orElseThrow(() -> new IllegalArgumentException(String.format("No enum constant for algorithm: %s", algorithm)));
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
