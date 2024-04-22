package io.opentdf.platform.sdk;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AsymDecryption {
    private PrivateKey privateKey;
    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    /**
     * <p>Constructor for AsymDecryption.</p>
     *
     * @param privateKeyInPem a Private Key in PEM format
     */
    public AsymDecryption(String privateKeyInPem) throws Exception {
        String privateKeyPEM = privateKeyInPem
                .replace(PRIVATE_KEY_HEADER, "")
                .replace(PRIVATE_KEY_FOOTER, "")
                .replaceAll("\\s", ""); // remove whitespaces

        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(spec);
    }

    /**
     * <p>decrypt.</p>
     *
     * @param data the data to decrypt
     * @return the decrypted data
     */
    public byte[] decrypt(byte[] data) throws Exception {
        if (this.privateKey == null) {
            throw new Exception("Failed to decrypt, private key is empty");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        return cipher.doFinal(data);
    }
}