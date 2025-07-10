package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Optional;

public class NanoTDFType {
    private static final Logger log = LoggerFactory.getLogger(NanoTDFType.class);
    enum ECCurve {
        SECP256R1("secp256r1", 32, 33, 0x00),
        SECP384R1("secp384r1", 48, 49, 0x01),
        SECP521R1("secp521r1", 66, 67, 0x02),
        SECP256K1("secp256k1",-1, -1, -1, false); // Note: SECP256K1 is not supported by the SDK

        private final int curveMode;
        private final int keySize;
        // compressedPubKeySize is a byte bigger since it encodes the X coordinate plus a byte that tells
        // if the Y coordinate is positive or negative
        private final int compressedPubKeySize;
        private final String curveName;
        private final boolean isSupported;


        ECCurve(String curveName, int keySize, int compressedPubKeySize, int curveMode) {
            this(curveName, keySize, compressedPubKeySize, curveMode, true);
        }

        ECCurve(String curveName, int keySize, int compressedPubKeySize, int curveMode, boolean isSupported) {
            this.curveName = curveName ;
            this.keySize = keySize;
            this.compressedPubKeySize = compressedPubKeySize;
            this.curveMode = curveMode;
            this.isSupported = isSupported;
        }

        @Nonnull
        static ECCurve fromCurveMode(int curveMode) {
            for (ECCurve curve : ECCurve.values()) {
                if (curve.getCurveMode() == curveMode) {
                    return curve;
                }
            }
            throw new IllegalArgumentException("No enum constant for curve mode: " + curveMode);
        }

        static Optional<ECCurve> fromAlgorithm(String platformAlgorithm) {
            log.debug("looking for platformAlgorithm [{}]", platformAlgorithm);
            if (platformAlgorithm == null) {
                return Optional.empty();
            }
            return Arrays.stream(ECCurve.values())
                    .filter(v -> v.getPlatformCurveName().equals(platformAlgorithm))
                    .findAny();
        }

        int getCurveMode() {
            return curveMode;
        }

        int getKeySize() {
            return keySize;
        }

        int getCompressedPubKeySize() {
            return compressedPubKeySize;
        }

        String getCurveName() {
            return curveName;
        }

        String getPlatformCurveName() {
            return String.format("ec:%s", curveName);
        }

        boolean isSupported() {
            return isSupported;
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
