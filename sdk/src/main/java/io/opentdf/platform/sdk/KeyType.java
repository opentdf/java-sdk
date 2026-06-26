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
    /**
     * Hybrid X-Wing (X25519 + ML-KEM-768). Requires {@code sdk-pqc-bc} (or another
     * {@link io.opentdf.platform.sdk.spi.KemProvider} implementation) on the runtime
     * classpath; not available under the fips Maven profile.
     */
    HybridXWingKey("hpqt:xwing"),
    /**
     * Hybrid P-256 + ML-KEM-768 per draft-ietf-lamps-pq-composite-kem-14. Requires
     * {@code sdk-pqc-bc} (or another {@link io.opentdf.platform.sdk.spi.KemProvider}
     * implementation) on the runtime classpath; not available under the fips Maven profile.
     */
    HybridSecp256r1MLKEM768Key("hpqt:secp256r1-mlkem768"),
    /**
     * Hybrid P-384 + ML-KEM-1024 per draft-ietf-lamps-pq-composite-kem-14. Requires
     * {@code sdk-pqc-bc} (or another {@link io.opentdf.platform.sdk.spi.KemProvider}
     * implementation) on the runtime classpath; not available under the fips Maven profile.
     */
    HybridSecp384r1MLKEM1024Key("hpqt:secp384r1-mlkem1024"),
    /**
     * Pure ML-KEM-768 (FIPS 203). Requires {@code sdk-pqc-bc} (or another
     * {@link io.opentdf.platform.sdk.spi.KemProvider} implementation) on the runtime
     * classpath; not available under the fips Maven profile.
     */
    MLKEM768Key("mlkem:768"),
    /**
     * Pure ML-KEM-1024 (FIPS 203). Requires {@code sdk-pqc-bc} (or another
     * {@link io.opentdf.platform.sdk.spi.KemProvider} implementation) on the runtime
     * classpath; not available under the fips Maven profile.
     */
    MLKEM1024Key("mlkem:1024");

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
            case ALGORITHM_HPQT_XWING:
                return KeyType.HybridXWingKey;
            case ALGORITHM_HPQT_SECP256R1_MLKEM768:
                return KeyType.HybridSecp256r1MLKEM768Key;
            case ALGORITHM_HPQT_SECP384R1_MLKEM1024:
                return KeyType.HybridSecp384r1MLKEM1024Key;
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
            case KAS_PUBLIC_KEY_ALG_ENUM_HPQT_XWING:
                return KeyType.HybridXWingKey;
            case KAS_PUBLIC_KEY_ALG_ENUM_HPQT_SECP256R1_MLKEM768:
                return KeyType.HybridSecp256r1MLKEM768Key;
            case KAS_PUBLIC_KEY_ALG_ENUM_HPQT_SECP384R1_MLKEM1024:
                return KeyType.HybridSecp384r1MLKEM1024Key;
            default:
                throw new IllegalArgumentException(
                        "Unsupported KAS public-key algorithm: " + algorithm
                        + ". See KeyType.java for currently-supported algorithms.");
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

    public boolean isMLKEM() {
        switch (this) {
            case MLKEM768Key:
            case MLKEM1024Key:
                return true;
            default:
                return false;
        }
    }
}
