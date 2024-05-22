package io.opentdf.platform.sdk;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AesGcm {
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    private static final int GCM_TAG_LENGTH = 16; // in bytes
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";

    private final SecretKey key;

    /**
     * <p>Constructor for AesGcm.</p>
     *
     * @param key secret key for encryption and decryption
     */
    public AesGcm(byte[] key) {
        if (key.length == 0) {
            throw new IllegalArgumentException("Invalid key size for gcm encryption");
        }
        this.key = new SecretKeySpec(key, "AES");
    }

    /**
     * <p>encrypt.</p>
     *
     * @param plaintext the plaintext to encrypt
     * @return the encrypted text
     */
    public byte[] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(plaintext, 0, plaintext.length);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param plaintext the plaintext byte array to encrypt
     * @param offset where the input start
     * @param len input length
     * @return the encrypted text
     */
    public byte[] encrypt(byte[] plaintext, int offset, int len) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] cipherText = cipher.doFinal(plaintext, offset, len);
        byte[] cipherTextWithNonce = new byte[nonce.length + cipherText.length];
        System.arraycopy(nonce, 0, cipherTextWithNonce, 0, nonce.length);
        System.arraycopy(cipherText, 0, cipherTextWithNonce, nonce.length, cipherText.length);
        return cipherTextWithNonce;
    }

    /**
     * <p>decrypt.</p>
     *
     * @param cipherTextWithNonce the ciphertext with nonce to decrypt
     * @return the decrypted text
     */
    public byte[] decrypt(byte[] cipherTextWithNonce) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        byte[] nonce = Arrays.copyOfRange(cipherTextWithNonce, 0, GCM_NONCE_LENGTH);
        byte[] cipherText = Arrays.copyOfRange(cipherTextWithNonce, GCM_NONCE_LENGTH, cipherTextWithNonce.length);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherText);
    }
}
