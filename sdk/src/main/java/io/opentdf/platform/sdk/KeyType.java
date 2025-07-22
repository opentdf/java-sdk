package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.policy.KasPublicKeyAlgEnum;

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

    public static KeyType fromAlgorithm(Algorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        switch (algorithm) {
            case ALGORITHM_RSA_2048:
                return KeyType.RSA2048Key;
            case ALGORITHM_EC_P256:
                return KeyType.EC256Key;
            case ALGORITHM_EC_P384:
                return KeyType.EC384Key;
            case ALGORITHM_EC_P521:
                return KeyType.EC521Key;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    public static KeyType fromAlgorithm(KasPublicKeyAlgEnum algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        switch (algorithm) {
            case KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
                return KeyType.RSA2048Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
                return KeyType.EC256Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
                return KeyType.EC384Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
                return KeyType.EC521Key;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    public boolean isEc() {
        return this.curve == SECP256R1 || this.curve == SECP384R1 || this.curve == SECP521R1;
    }
}