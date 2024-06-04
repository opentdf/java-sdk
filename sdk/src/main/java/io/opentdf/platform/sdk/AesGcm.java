package io.opentdf.platform.sdk;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AesGcm {
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    private static final int GCM_TAG_LENGTH = 16; // in bytes
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";

    private final SecretKey key;

    public static class Encrypted {
        private final byte[] iv;
        private final byte[] ciphertext;

        public byte[] getIv() {
            return iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public Encrypted(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        public Encrypted(byte[] ivAndCiphertext) {
            if (ivAndCiphertext.length < GCM_NONCE_LENGTH) {
                throw new IllegalArgumentException("too short for IV and ciphertext");
            }
            this.iv = new byte[GCM_NONCE_LENGTH];
            this.ciphertext = new byte[ivAndCiphertext.length - GCM_NONCE_LENGTH];

            System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);
            System.arraycopy(ivAndCiphertext, GCM_NONCE_LENGTH, ciphertext, 0, ciphertext.length);
        }

        public byte[] asBytes() {
            byte[] out = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
            return out;
        }
    }

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
    public Encrypted encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException,
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
    public Encrypted encrypt(byte[] plaintext, int offset, int len) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] cipherText = cipher.doFinal(plaintext, offset, len);

        return new Encrypted(nonce, cipherText);
    }

    /**
     * <p>decrypt.</p>
     *
     * @param cipherTextWithNonce the ciphertext with nonce to decrypt
     * @return the decrypted text
     */
    public byte[] decrypt(Encrypted cipherTextWithNonce) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, cipherTextWithNonce.iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherTextWithNonce.ciphertext);
    }
}
