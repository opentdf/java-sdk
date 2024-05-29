package io.opentdf.platform.sdk;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public class AsymEncryption {
    private final PublicKey publicKey;
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    /**
     * <p>Constructor for AsymEncryption.</p>
     *
     * @param publicKeyInPem a Public Key in PEM format
     */
    public AsymEncryption(String publicKeyInPem) {
        publicKeyInPem = publicKeyInPem
                .replace(PUBLIC_KEY_HEADER, "")
                .replace(PUBLIC_KEY_FOOTER, "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyInPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("RSA is not a valid algorithm!!!???!!!", e);
        }

        try {
            this.publicKey = kf.generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            throw new SDKException("error creating asymmetric encryption", e);
        }
    }

    public AsymEncryption(PublicKey publicKey) {
       this.publicKey = Objects.requireNonNull(publicKey);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param data the data to encrypt
     * @return the encrypted data
     */
    public byte[] encrypt(byte[] data) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SDKException("error getting instance of cipher during encryption", e);
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        } catch (InvalidKeyException e) {
            throw new SDKException("error encrypting with private key", e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new SDKException("error performing encryption", e);
        }
    }

    /**
     * <p>publicKeyInPemFormat.</p>
     * @return the public key in PEM format
     */
    public String publicKeyInPemFormat() throws Exception {
        String publicKeyPem = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
        return PUBLIC_KEY_HEADER + '\n' + publicKeyPem + '\n' + PUBLIC_KEY_FOOTER + '\n';
    }
}