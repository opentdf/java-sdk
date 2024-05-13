package io.opentdf.platform.sdk.nanotdf;

import java.security.*;
import java.security.spec.*;

public class ECKeyPair {
    private static final String SECP256R1_CURVE = "secp256r1";
    private static final String PRIME256V1_CURVE = "prime256v1";
    private static final String SECP384R1_CURVE = "secp384r1";
    private static final String SECP521R1_CURVE = "secp521r1";
    private KeyPair keyPair;

    public ECKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        this.keyPair = keyGen.generateKeyPair();
    }

    public PublicKey getPublicKey() {
        return this.keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.keyPair.getPrivate();
    }

    public static ECKeyPair generate(String curveName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec(curveName));
        KeyPair keyPair = keyGen.generateKeyPair();
        ECKeyPair ecKeyPair = new ECKeyPair();
        ecKeyPair.keyPair = keyPair;
        return ecKeyPair;
    }

    public static int getECKeySize(String curveName) {
        if (curveName.equalsIgnoreCase(SECP256R1_CURVE) ||
                curveName.equalsIgnoreCase(PRIME256V1_CURVE)) {
            return 32;
        } else if (curveName.equalsIgnoreCase(SECP384R1_CURVE)) {
            return 48;
        } else if (curveName.equalsIgnoreCase(SECP521R1_CURVE)) {
            return 66;
        } else {
            throw new IllegalArgumentException("Unsupported ECC algorithm.");
        }
    }

    public String publicKeyInPEMFormat() {
        //TODO: convert keys to PEM format
        return null;
    }

    public String privateKeyInPEMFormat() {
        //TODO: convert keys to PEM format
        return null;
    }

    public int keySize() {
        return this.keyPair.getPrivate().getEncoded().length * 8;
    }

    public String curveName() {
        // Java does not provide a built-in way to get the curve name from a key
        // You would need to parse the key's algorithm parameters to get the curve name
        return null;
    }
}