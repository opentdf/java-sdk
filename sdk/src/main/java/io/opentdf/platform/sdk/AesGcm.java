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
    public byte[] encrypt(byte[] plaintext) {
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
    public byte[] encrypt(byte[] plaintext, int offset, int len)  {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        try {
            SecureRandom.getInstanceStrong().nextBytes(nonce);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        byte[] cipherText = new byte[0];
        try {
            cipherText = cipher.doFinal(plaintext, offset, len);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
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
