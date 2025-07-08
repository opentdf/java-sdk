package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Algorithm;

import java.util.Set;

public enum KeyType {
    RSA2048Key("rsa:2048"),
    EC256Key("ec:secp256r1"),
    EC384Key("ec:secp384r1"),
    EC521Key("ec:secp521r1");

    private final String keyType;

    KeyType(String keyType) {
        this.keyType = keyType;
    }

    @Override
    public String toString() {
        return keyType;
    }

    public String getCurveName() {
        switch (this) {
            case EC256Key:
                return "secp256r1";
            case EC384Key:
                return "secp384r1";
            case EC521Key:
                return "secp521r1";
            default:
                throw new IllegalArgumentException("Unsupported key type: " + this);
        }
    }

    public static KeyType fromString(String keyType) {
        for (KeyType type : KeyType.values()) {
            if (type.keyType.equalsIgnoreCase(keyType)) {
                return type;
            }
        }
        throw new IllegalArgumentException("No enum constant for key type: " + keyType);
    }

    public static KeyType fromAlgorithm(Algorithm a) {
        switch (a) {
            case ALGORITHM_RSA_2048:
                return RSA2048Key;
            case ALGORITHM_EC_P256:
                return EC256Key;
            case ALGORITHM_EC_P384:
                return EC384Key;
            case ALGORITHM_EC_P521:
                return EC521Key;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + a);
        }
    }

    private static final Set<KeyType> EC_KEY_TYPES = Set.of(EC256Key, EC384Key, EC521Key);

    public boolean isEc() {
        return EC_KEY_TYPES.contains(this);
    }
}