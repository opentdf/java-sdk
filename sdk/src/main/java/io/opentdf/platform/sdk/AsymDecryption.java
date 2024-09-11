package io.opentdf.platform.sdk;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AsymDecryption {
    private final PrivateKey privateKey;
    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    /**
     * <p>Constructor for AsymDecryption.</p>
     *
     * @param privateKeyInPem a Private Key in PEM format
     */
    public AsymDecryption(String privateKeyInPem) {
        String privateKeyPEM = privateKeyInPem
                .replace(PRIVATE_KEY_HEADER, "")
                .replace(PRIVATE_KEY_FOOTER, "")
                .replaceAll("\\s", ""); // remove whitespaces

        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            this.privateKey = kf.generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public AsymDecryption(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * <p>decrypt.</p>
     *
     * @param data the data to decrypt
     * @return the decrypted data
     */
    public byte[] decrypt(byte[] data) {
        if (this.privateKey == null) {
            throw new SDKException("Failed to decrypt, private key is empty");
        }

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SDKException("error getting instance of cipher", e);
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        } catch (InvalidKeyException e) {
            throw new SDKException("error initializing cipher", e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new SDKException("error performing decryption", e);
        }
    }
}