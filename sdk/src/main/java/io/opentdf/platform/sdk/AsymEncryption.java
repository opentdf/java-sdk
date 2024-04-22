package io.opentdf.platform.sdk;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymEncryption {
    private PublicKey publicKey;
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    /**
     * <p>Constructor for AsymEncryption.</p>
     *
     * @param publicKeyInPem a Public Key in PEM format
     */
    public AsymEncryption(String publicKeyInPem) throws Exception {
        publicKeyInPem = publicKeyInPem
                .replace(PUBLIC_KEY_HEADER, "")
                .replace(PUBLIC_KEY_FOOTER, "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyInPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.publicKey = kf.generatePublic(spec);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param data the data to encrypt
     * @return the encrypted data
     */
    public byte[] encrypt(byte[] data) throws Exception {
        if (this.publicKey == null) {
            throw new Exception("Failed to encrypt, public key is empty");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        return cipher.doFinal(data);
    }

    /**
     * <p>publicKeyInPemFormat.</p>
     * @return the public key in PEM format
     */
    public String publicKeyInPemFormat() throws Exception {
        if (this.publicKey == null) {
            throw new Exception("Failed to generate PEM formatted public key");
        }

        String publicKeyPem = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
        return PUBLIC_KEY_HEADER + '\n' + publicKeyPem + '\n' + PUBLIC_KEY_FOOTER + '\n';
    }
}