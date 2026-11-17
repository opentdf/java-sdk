package io.opentdf.platform.sdk;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The AesGcm class provides encryption and decryption methods using AES-GCM mode.
 * It includes methods to encrypt and decrypt byte arrays using a specified
 * symmetric key.
 */
public class AesGcm {
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16; // in bytes
    public static final int GCM_KEY_SIZE_BITS = 256;
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";

    private final SecretKey key;

    /**
     * <p>Generate a fresh 256-bit AES key using the JCA {@link KeyGenerator}.</p>
     *
     * @return the encoded key bytes
     */
    static byte[] generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(GCM_KEY_SIZE_BITS);
            return keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error generating AES key", e);
        }
    }


    /**
     * <p>Return symmetric key</p>
     *
     * @return
     */
    public byte[] getKey() {
        return key.getEncoded();
    }

    /**
     * A complete AES-GCM message: a {@value #GCM_NONCE_LENGTH}-byte IV, the ciphertext, and
     * the {@value #GCM_TAG_LENGTH}-byte tag the cipher computed over them, held as one
     * contiguous {@code iv || ciphertext || tag} buffer.
     * <p>
     * Every instance is at least {@link #MIN_LENGTH} bytes, so {@link #authTag()} is total:
     * it always returns bytes that sit where an AEAD tag sits in a well-formed message,
     * never a sixteen-byte slice of something too short to be one. That invariant is why
     * {@code TDF.segmentIntegrity} takes this type rather than a {@code byte[]} — the GMAC
     * branch cannot be reached with a value, such as the aggregate hash, that never went
     * through the cipher.
     * <p>
     * <b>What this does not do:</b> the public constructors accept arbitrary bytes, so an
     * instance is not proof that its contents came out of a cipher. On the read path they
     * are attacker-supplied by definition, and it is the tag check in
     * {@link AesGcm#decrypt(Encrypted)} that catches a forgery. What the type rules out is
     * the API misuse of treating a value that is not an AEAD output as though it were one.
     */
    public static final class Encrypted {
        /** The shortest well-formed AES-GCM message: an IV, an empty plaintext, and a tag. */
        static final int MIN_LENGTH = GCM_NONCE_LENGTH + GCM_TAG_LENGTH;

        /** Exactly {@code iv || ciphertext || tag}; never shorter than {@link #MIN_LENGTH}. */
        private final byte[] buf;

        /**
         * Distinguishes the no-copy constructor from {@link #Encrypted(byte[])}, which has
         * the same erasure, and marks the hand-off as an ownership transfer at each use.
         */
        private enum Ownership {
            TRANSFERRED
        }

        private Encrypted(byte[] owned, Ownership transfer) {
            this.buf = owned;
        }

        /**
         * @param ivAndCiphertext a whole AES-GCM message, {@code iv || ciphertext || tag},
         *                        which is copied
         */
        public Encrypted(byte[] ivAndCiphertext) {
            this(requireWellFormed(ivAndCiphertext).clone(), Ownership.TRANSFERRED);
        }

        /**
         * @param iv               the {@value #GCM_NONCE_LENGTH}-byte IV
         * @param ciphertextAndTag the ciphertext with its trailing
         *                         {@value #GCM_TAG_LENGTH}-byte tag
         */
        public Encrypted(byte[] iv, byte[] ciphertextAndTag) {
            this(join(iv, ciphertextAndTag), Ownership.TRANSFERRED);
        }

        /**
         * Takes ownership of {@code ivCiphertextAndTag} instead of copying it. The caller
         * must not retain or mutate the array afterwards.
         * <p>
         * For buffers this SDK allocated and will not touch again — a freshly read segment,
         * or the output of {@link AesGcm#encryptInto}. Use {@link #Encrypted(byte[])}
         * anywhere the array has another owner.
         */
        static Encrypted wrapping(byte[] ivCiphertextAndTag) {
            return new Encrypted(requireWellFormed(ivCiphertextAndTag), Ownership.TRANSFERRED);
        }

        private static byte[] requireWellFormed(byte[] ivAndCiphertext) {
            if (ivAndCiphertext.length < MIN_LENGTH) {
                throw new IllegalArgumentException("too short to be an AES-GCM message: "
                        + ivAndCiphertext.length + " bytes, need at least " + MIN_LENGTH + " ("
                        + GCM_NONCE_LENGTH + "-byte IV + " + GCM_TAG_LENGTH + "-byte tag)");
            }
            return ivAndCiphertext;
        }

        private static byte[] join(byte[] iv, byte[] ciphertextAndTag) {
            if (iv == null || iv.length != GCM_NONCE_LENGTH) {
                throw new IllegalArgumentException("invalid IV size for an AES-GCM message: "
                        + (iv == null ? "null" : iv.length) + ", need " + GCM_NONCE_LENGTH);
            }
            if (ciphertextAndTag == null || ciphertextAndTag.length < GCM_TAG_LENGTH) {
                throw new IllegalArgumentException("ciphertext is too short to carry a tag: "
                        + (ciphertextAndTag == null ? "null" : ciphertextAndTag.length)
                        + " bytes, need at least " + GCM_TAG_LENGTH);
            }
            byte[] joined = new byte[iv.length + ciphertextAndTag.length];
            System.arraycopy(iv, 0, joined, 0, iv.length);
            System.arraycopy(ciphertextAndTag, 0, joined, iv.length, ciphertextAndTag.length);
            return joined;
        }

        public byte[] getIv() {
            return Arrays.copyOf(buf, GCM_NONCE_LENGTH);
        }

        /**
         * @return the ciphertext together with its trailing {@value #GCM_TAG_LENGTH}-byte tag
         */
        public byte[] getCiphertext() {
            return Arrays.copyOfRange(buf, GCM_NONCE_LENGTH, buf.length);
        }

        /**
         * @return a copy of the whole message, {@code iv || ciphertext || tag}
         */
        public byte[] asBytes() {
            return buf.clone();
        }

        /**
         * The authentication tag AES-GCM produced over exactly the rest of this message.
         * <p>
         * A genuine MAC only because the value is a whole AEAD output: the tag is keyed and
         * covers the bytes it accompanies. The same sixteen-byte slice taken off something
         * that never passed through the cipher — an aggregate hash, say — is not a MAC at
         * all, but a copy of that input's own trailing bytes, keyless and forgeable by
         * whoever supplied them. Requiring this type is what keeps the two apart; see
         * {@code TDF.segmentIntegrity} and {@code TDF.rootIntegrity}.
         *
         * @return the trailing {@value #GCM_TAG_LENGTH} bytes, always present
         */
        byte[] authTag() {
            return Arrays.copyOfRange(buf, buf.length - GCM_TAG_LENGTH, buf.length);
        }

        /**
         * The backing {@code iv || ciphertext || tag} buffer, <b>not</b> copied.
         * <p>
         * For in-package callers that only read it: the payload writer, and the HS256 branch
         * of {@code TDF.segmentIntegrity}, which must authenticate the whole message.
         * Mutating it corrupts this instance. Use {@link #asBytes()} anywhere else.
         */
        byte[] bytesNoCopy() {
            return buf;
        }

        /**
         * @return the length of the whole message, which is what a TDF records as its
         *         {@code encryptedSegmentSize}
         */
        int size() {
            return buf.length;
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
    public Encrypted encrypt(byte[] plaintext) {
        return encrypt(plaintext, 0, plaintext.length);
    }

    /**
     * <p>encrypt.</p>
     *
     * <p><b>Generates a fresh random nonce from {@link SecureRandom} for every call.</b> A
     * random 96-bit nonce is only safe for a modest number of invocations under one key, so use
     * this overload only with a key used once or a very small number of times. To encrypt many
     * messages under a single key, use
     * {@link #encrypt(byte[], int, byte[], int, int)} with a counter that never repeats.</p>
     *
     * @param plaintext the plaintext byte array to encrypt
     * @param offset where the input start
     * @param len input length
     * @return the encrypted text
     */
    public Encrypted encrypt(byte[] plaintext, int offset, int len) {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        try {
            SecureRandom.getInstanceStrong().nextBytes(nonce);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return encryptInto(nonce, plaintext, offset, len);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param iv the IV vector, which must be {@value #GCM_NONCE_LENGTH} bytes and must never be
     *           reused under this key
     * @param plaintext the plaintext byte array to encrypt
     * @param offset where the input start
     * @param len input length
     * @return the whole AES-GCM message: the IV, the ciphertext and the tag
     */
    public Encrypted encrypt(byte[] iv, byte[] plaintext, int offset, int len) {
        return encryptInto(iv, plaintext, offset, len);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param iv the IV vector, which must be {@value #GCM_NONCE_LENGTH} bytes and must never be
     *           reused under this key
     * @param authTagLen the length of the auth tag, which must be {@value #GCM_TAG_LENGTH}
     * @param plaintext the plaintext byte array to encrypt
     * @param offset where the input start
     * @param len input length
     * @return the encrypted text, prefixed with the IV
     * @deprecated use {@link #encrypt(byte[], byte[], int, int)}, which returns the
     *             {@link Encrypted} the rest of the SDK works in terms of. The tag length was
     *             never variable — this overload only ever accepted
     *             {@value #GCM_TAG_LENGTH}.
     */
    @Deprecated
    public byte[] encrypt(byte[] iv, int authTagLen, byte[] plaintext, int offset, int len) {
        // strict, because the read path assumes this length: Encrypted splits at
        // GCM_NONCE_LENGTH and TDF validates segment sizes against GCM_TAG_LENGTH, so any other
        // value would write a TDF this SDK cannot read
        if (authTagLen != GCM_TAG_LENGTH) {
            throw new IllegalArgumentException("invalid auth tag length for gcm encryption: " + authTagLen);
        }
        return encryptInto(iv, plaintext, offset, len).asBytes();
    }

    /**
     * Encrypts into one contiguous {@code iv || ciphertext || tag} buffer, the single place
     * in the SDK that produces that layout.
     * <p>
     * The cipher writes straight into the final buffer, so no segment-sized copy is made.
     * The provider's output size is checked against the AES-GCM contract rather than
     * assumed: a provider that disagrees fails loudly here instead of quietly writing a TDF
     * this SDK could not read back.
     */
    private Encrypted encryptInto(byte[] iv, byte[] plaintext, int offset, int len) {
        if (iv == null || iv.length != GCM_NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "invalid IV size for gcm encryption: " + (iv == null ? "null" : iv.length));
        }
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));

            int outputSize = cipher.getOutputSize(len);
            if (outputSize != len + GCM_TAG_LENGTH) {
                throw new SDKException("unexpected AES-GCM output size: " + outputSize
                        + " for " + len + " bytes of plaintext, expected " + (len + GCM_TAG_LENGTH));
            }

            byte[] buf = new byte[GCM_NONCE_LENGTH + outputSize];
            System.arraycopy(iv, 0, buf, 0, GCM_NONCE_LENGTH);

            int written = cipher.doFinal(plaintext, offset, len, buf, GCM_NONCE_LENGTH);
            if (written != outputSize) {
                throw new SDKException("AES-GCM wrote " + written + " bytes, expected " + outputSize);
            }
            return Encrypted.wrapping(buf);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException
                | ShortBufferException e) {
            throw new SDKException("error gcm encrypt", e);
        }
    }

    /**
     * <p>decrypt.</p>
     *
     * @param cipherTextWithNonce the ciphertext with nonce to decrypt
     * @return the decrypted text
     */
    public byte[] decrypt(Encrypted cipherTextWithNonce)  {
        try {
            byte[] buf = cipherTextWithNonce.bytesNoCopy();
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new GCMParameterSpec(GCM_TAG_LENGTH * 8, buf, 0, GCM_NONCE_LENGTH));
            return cipher.doFinal(buf, GCM_NONCE_LENGTH, buf.length - GCM_NONCE_LENGTH);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SDKException("error gcm decrypt", e);
        }
    }

    /**
     * <p>decrypt.</p>
     *
     * @param iv the IV vector
     * @param authTagLen the length of the auth tag
     * @param cipherData the cipherData byte array to decrypt
     * @return the decrypted data
     * @deprecated use {@link #decrypt(Encrypted)}. Passing an IV, a tag length and a
     *             detached {@code byte[]} separately is the shape this SDK is moving away
     *             from: it cannot express that the three belong to one AES-GCM message.
     */
    @Deprecated
    public byte[] decrypt(byte[] iv, int authTagLen, byte[] cipherData) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            GCMParameterSpec spec = new GCMParameterSpec(authTagLen * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(cipherData);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("error gcm decrypt", e);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SDKException("error gcm decrypt", e);
        }
    }
}
