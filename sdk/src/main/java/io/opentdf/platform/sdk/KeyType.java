package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.policy.KasPublicKeyAlgEnum;

import javax.annotation.Nonnull;

import static io.opentdf.platform.sdk.ECCurve.SECP256R1;
import static io.opentdf.platform.sdk.ECCurve.SECP384R1;
import static io.opentdf.platform.sdk.ECCurve.SECP521R1;

public enum KeyType {
    RSA2048Key("rsa:2048"),
    RSA4096Key("rsa:4096"),
    EC256Key("ec:secp256r1", SECP256R1),
    EC384Key("ec:secp384r1", SECP384R1),
    EC521Key("ec:secp521r1", SECP521R1),
    HybridXWingKey("hpqt:xwing"),
    HybridSecp256r1MLKEM768Key("hpqt:secp256r1-mlkem768"),
    HybridSecp384r1MLKEM1024Key("hpqt:secp384r1-mlkem1024");

    private final String keyType;
    private final ECCurve curve;

    KeyType(String keyType, ECCurve ecCurve) {
        this.keyType = keyType;
        this.curve = ecCurve;
    }

    KeyType(String keyType) {
        this(keyType, null);
    }

    @Nonnull
    ECCurve getECCurve() {
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
            case ALGORITHM_RSA_4096:
                return KeyType.RSA4096Key;
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

    public static KeyType fromPublicKeyAlgorithm(KasPublicKeyAlgEnum algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        switch (algorithm) {
            case KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
                return KeyType.RSA2048Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:
                return KeyType.RSA4096Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
                return KeyType.EC256Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
                return KeyType.EC384Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
                return KeyType.EC521Key;
            default:
                // Hybrid PQC algorithms (HybridXWingKey, HybridSecp256r1MLKEM768Key,
                // HybridSecp384r1MLKEM1024Key) are not yet mapped here — the platform's
                // KasPublicKeyAlgEnum proto definitions don't include them at the time
                // of writing. When they do, add cases above. Callers can work around
                // this gap by setting --encap-key-type (cmdline) or
                // Config.WithWrappingKeyAlg (SDK), both of which bypass this mapping.
                throw new IllegalArgumentException(
                        "Unsupported KAS public-key algorithm: " + algorithm
                        + " — this may be a PQC algorithm not yet mapped by the SDK. "
                        + "See KeyType.java for currently-supported algorithms.");
        }
    }

    public boolean isEc() {
        return this.curve != null;
    }

    public boolean isHybrid() {
        switch (this) {
            case HybridXWingKey:
            case HybridSecp256r1MLKEM768Key:
            case HybridSecp384r1MLKEM1024Key:
                return true;
            default:
                return false;
        }
    }
}
