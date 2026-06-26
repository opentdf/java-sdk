package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Optional;

/**
 * Elliptic curve definitions for EC key operations.
 */
public enum ECCurve {
    SECP256R1("secp256r1", 32, 33, 0x00),
    SECP384R1("secp384r1", 48, 49, 0x01),
    SECP521R1("secp521r1", 66, 67, 0x02),
    SECP256K1("secp256k1", -1, -1, -1, false); // Note: SECP256K1 is not supported by the SDK

    private static final Logger log = LoggerFactory.getLogger(ECCurve.class);

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
        this.curveName = curveName;
        this.keySize = keySize;
        this.compressedPubKeySize = compressedPubKeySize;
        this.curveMode = curveMode;
        this.isSupported = isSupported;
    }

    @Nonnull
    public static ECCurve fromCurveMode(int curveMode) {
        for (ECCurve curve : ECCurve.values()) {
            if (curve.getCurveMode() == curveMode) {
                return curve;
            }
        }
        throw new IllegalArgumentException("No enum constant for curve mode: " + curveMode);
    }

    public static Optional<ECCurve> fromAlgorithm(String platformAlgorithm) {
        log.debug("looking for platformAlgorithm [{}]", platformAlgorithm);
        if (platformAlgorithm == null) {
            return Optional.empty();
        }
        return Arrays.stream(ECCurve.values())
                .filter(v -> v.getPlatformCurveName().equals(platformAlgorithm))
                .findAny();
    }

    public int getCurveMode() {
        return curveMode;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getCompressedPubKeySize() {
        return compressedPubKeySize;
    }

    public String getCurveName() {
        return curveName;
    }

    public String getPlatformCurveName() {
        return String.format("ec:%s", curveName);
    }

    public boolean isSupported() {
        return isSupported;
    }
}
