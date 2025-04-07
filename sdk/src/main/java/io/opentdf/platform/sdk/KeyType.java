package io.opentdf.platform.sdk;

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

    public boolean isEc() {
        return this != RSA2048Key;
    }
}