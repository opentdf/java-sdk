package io.opentdf.platform.sdk;

import javax.annotation.Nonnull;

import static io.opentdf.platform.sdk.NanoTDFType.ECCurve.SECP256R1;
import static io.opentdf.platform.sdk.NanoTDFType.ECCurve.SECP384R1;
import static io.opentdf.platform.sdk.NanoTDFType.ECCurve.SECP521R1;

public enum KeyType {
    RSA2048Key("rsa:2048"),
    EC256Key("ec:secp256r1", SECP256R1),
    EC384Key("ec:secp384r1", SECP384R1),
    EC521Key("ec:secp521r1", SECP521R1);

    private final String keyType;
    private final NanoTDFType.ECCurve curve;

    KeyType(String keyType, NanoTDFType.ECCurve ecCurve) {
        this.keyType = keyType;
        this.curve = ecCurve;
    }

    KeyType(String keyType) {
        this(keyType, null);
    }

    @Nonnull
    NanoTDFType.ECCurve getECCurve() {
        if (!isEc()) {
            throw new IllegalStateException("This key type does not have an ECCurve associated with it: " + keyType);
        }
        return curve;
    }

    @Override
    public String toString() {
        return keyType;
    }

    public static KeyType fromString(String keyType) {
        for (KeyType type : KeyType.values()) {
            if (type.keyType.equalsIgnoreCase(keyType)) {
                return type;
            }
        }
        throw new IllegalArgumentException("No enum constant for key type: " + keyType);
    }

    public boolean isEc() {
        return this.curve != null;
    }
}