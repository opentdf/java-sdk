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

        byte[] cipherText = aesGcm.encrypt(plaintext);
        byte[] decryptedText = aesGcm.decrypt(cipherText);

        assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    void decryptionWithModifiedCipherText() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] key = "ThisIsASecretKey".getBytes();
        AesGcm aesGcm = new AesGcm(key);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        byte[] cipherText = aesGcm.encrypt(plaintext);
        cipherText[0] = (byte) (cipherText[0] ^ 0x1); // Modify the ciphertext

        assertThrows(BadPaddingException.class, () -> aesGcm.decrypt(cipherText));
    }

    @Test
    void encryptionWithEmptyKey() {
        byte[] key = new byte[0];

        assertThrows(IllegalArgumentException.class, () -> new AesGcm(key));
    }
}