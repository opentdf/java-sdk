package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

class AesGcmTest {

    @Test
    void encryptionAndDecryptionWithValidKey() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] key = "ThisIsASecretKey".getBytes();
        AesGcm aesGcm = new AesGcm(key);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        var encrypted = aesGcm.encrypt(plaintext);
        byte[] decryptedText = aesGcm.decrypt(encrypted);

        assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    void decryptionWithModifiedCipherText() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] key = "ThisIsASecretKey".getBytes();
        AesGcm aesGcm = new AesGcm(key);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        var encrypted = aesGcm.encrypt(plaintext);
        var bytes = encrypted.asBytes();
        bytes[12] = (byte) (bytes[12]^1);
        assertThrows(RuntimeException.class, () -> aesGcm.decrypt(new AesGcm.Encrypted(bytes)));
    }

    @Test
    void encryptionWithEmptyKey() {
        byte[] key = new byte[0];

        assertThrows(IllegalArgumentException.class, () -> new AesGcm(key));
    }

    // ------------------------------------------------- supplied-IV encryption

    private static final byte[] KEY = "ThisIsASecretKey".getBytes();

    /** Fixed so the two encrypt overloads can be compared byte for byte. */
    private static byte[] iv() {
        byte[] iv = new byte[AesGcm.GCM_NONCE_LENGTH];
        for (int index = 0; index < iv.length; index++) {
            iv[index] = (byte) index;
        }
        return iv;
    }

    @Test
    void encryptionWithSuppliedIvRoundTrips() {
        var aesGcm = new AesGcm(KEY);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        var encrypted = aesGcm.encrypt(iv(), plaintext, 0, plaintext.length);

        assertEquals(AesGcm.GCM_NONCE_LENGTH + plaintext.length + AesGcm.GCM_TAG_LENGTH,
                encrypted.size());
        assertArrayEquals(iv(), encrypted.getIv());
        assertArrayEquals(plaintext, aesGcm.decrypt(encrypted));
    }

    /**
     * Guards the migration: the {@link AesGcm.Encrypted}-returning overload must lay bytes out
     * exactly the way the deprecated one did, or it would change the TDF wire format.
     */
    @Test
    @SuppressWarnings("deprecation")
    void newAndDeprecatedEncryptOverloadsProduceIdenticalBytes() {
        var aesGcm = new AesGcm(KEY);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        byte[] viaDeprecated = aesGcm.encrypt(iv(), AesGcm.GCM_TAG_LENGTH, plaintext, 0, plaintext.length);
        byte[] viaEncrypted = aesGcm.encrypt(iv(), plaintext, 0, plaintext.length).asBytes();

        assertArrayEquals(viaDeprecated, viaEncrypted);
    }

    @Test
    @SuppressWarnings("deprecation")
    void deprecatedEncryptStillRejectsANonStandardTagLength() {
        var aesGcm = new AesGcm(KEY);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        assertThrows(IllegalArgumentException.class,
                () -> aesGcm.encrypt(iv(), 12, plaintext, 0, plaintext.length));
    }

    @Test
    void encryptionRejectsAnIvOfTheWrongSize() {
        var aesGcm = new AesGcm(KEY);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        assertThrows(IllegalArgumentException.class,
                () -> aesGcm.encrypt(new byte[8], plaintext, 0, plaintext.length));
    }

    // ---------------------------------------------------- the Encrypted type

    /**
     * The boundary that makes {@link AesGcm.Encrypted#authTag()} total: even an empty
     * plaintext produces a full IV and tag, so there is no shorter well-formed message.
     */
    @Test
    void emptyPlaintextStillCarriesAnIvAndATag() {
        var encrypted = new AesGcm(KEY).encrypt(iv(), new byte[0], 0, 0);

        assertEquals(AesGcm.Encrypted.MIN_LENGTH, encrypted.size());
        assertArrayEquals(new byte[0], new AesGcm(KEY).decrypt(encrypted));
    }

    @Test
    void encryptedRejectsAMessageTooShortToHoldAnIvAndTag() {
        assertThrows(IllegalArgumentException.class,
                () -> new AesGcm.Encrypted(new byte[AesGcm.Encrypted.MIN_LENGTH - 1]));
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.Encrypted.wrapping(new byte[AesGcm.Encrypted.MIN_LENGTH - 1]));

        // exactly at the boundary is well-formed, whether or not it authenticates
        assertEquals(AesGcm.Encrypted.MIN_LENGTH,
                new AesGcm.Encrypted(new byte[AesGcm.Encrypted.MIN_LENGTH]).size());
    }

    @Test
    void encryptedRejectsAMalformedIvOrCiphertext() {
        assertThrows(IllegalArgumentException.class,
                () -> new AesGcm.Encrypted(new byte[8], new byte[AesGcm.GCM_TAG_LENGTH]));
        assertThrows(IllegalArgumentException.class,
                () -> new AesGcm.Encrypted(new byte[AesGcm.GCM_NONCE_LENGTH],
                        new byte[AesGcm.GCM_TAG_LENGTH - 1]));
    }

    @Test
    void authTagIsTheTrailingSixteenBytesOfTheMessage() {
        var plaintext = "Virtru, JavaSDK!".getBytes();
        var encrypted = new AesGcm(KEY).encrypt(iv(), plaintext, 0, plaintext.length);

        var bytes = encrypted.asBytes();
        var expected = new byte[AesGcm.GCM_TAG_LENGTH];
        System.arraycopy(bytes, bytes.length - expected.length, expected, 0, expected.length);

        assertArrayEquals(expected, encrypted.authTag());
    }

    /**
     * The accessors hand out copies, so a caller cannot corrupt the message it was given.
     */
    @Test
    void accessorsDoNotAliasTheBackingBuffer() {
        var plaintext = "Virtru, JavaSDK!".getBytes();
        var aesGcm = new AesGcm(KEY);
        var encrypted = aesGcm.encrypt(iv(), plaintext, 0, plaintext.length);
        var original = encrypted.asBytes();

        encrypted.asBytes()[0] ^= 0xFF;
        encrypted.getIv()[0] ^= 0xFF;
        encrypted.getCiphertext()[0] ^= 0xFF;
        encrypted.authTag()[0] ^= 0xFF;

        assertArrayEquals(original, encrypted.asBytes());
        assertArrayEquals(plaintext, aesGcm.decrypt(encrypted));
    }

    /** {@code Encrypted(byte[])} copies; {@code wrapping} deliberately does not. */
    @Test
    void constructorCopiesWhileWrappingTakesOwnership() {
        var plaintext = "Virtru, JavaSDK!".getBytes();
        var source = new AesGcm(KEY).encrypt(iv(), plaintext, 0, plaintext.length).asBytes();

        var copied = new AesGcm.Encrypted(source);
        var wrapped = AesGcm.Encrypted.wrapping(source);

        assertNotSame(source, copied.bytesNoCopy());
        assertSame(source, wrapped.bytesNoCopy());
    }

    @Test
    void ivAndCiphertextTogetherReconstituteTheMessage() {
        var plaintext = "Virtru, JavaSDK!".getBytes();
        var encrypted = new AesGcm(KEY).encrypt(iv(), plaintext, 0, plaintext.length);

        var rebuilt = new AesGcm.Encrypted(encrypted.getIv(), encrypted.getCiphertext());

        assertArrayEquals(encrypted.asBytes(), rebuilt.asBytes());
    }
}