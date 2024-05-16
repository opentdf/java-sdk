package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class AsymEncryptionTest {

    @Test
    void encryptionWithValidPublicKey() throws Exception {
        String publicKeyInPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvKYimFpxEp58ZGTgiaP\n" +
                "RYEzrikTZ3GP0KhWIYrQFAbWdE0qvSS+8LxcUDQoisFk1ux1CO9iuUlyZdKeGsbz\n" +
                "sTmJjdk4nHoH5f/BiLzTEJemDIjXPV5vYcY++4QKhFbZf/XLLZ2hSzAuXz5ZOCel\n" +
                "A/KZs+Zb19Vlra5DCDJ43mqdoqFIDS4cl8mtuRDC5Uw3x1S52tnO/TKPDGj32aVS\n" +
                "GBKh0CWGAXWRmphzGj7kFpkAxT1b827MrQMYxkn4w2WB8B/bGKz0+dWyqnnzGYAS\n" +
                "hVJ0rIiNE8dDWzQCRBfivLemXhX8UFICyoS5i0IwenFvTr6T85EvMxK3aSAlGya3\n" +
                "3wIDAQAB\n" +
                "-----END PUBLIC KEY-----";;
        AsymEncryption asymEncryption = new AsymEncryption(publicKeyInPem);
        byte[] plaintext = "Virtru, JavaSDK!".getBytes();

        byte[] cipherText = asymEncryption.encrypt(plaintext);

        assertNotNull(cipherText);
    }

    @Test
    void encryptionWithInvalidPublicKey() {
        String publicKeyInPem = "InvalidPublicKey";

        assertThrows(Exception.class, () -> new AsymEncryption(publicKeyInPem));
    }

    @Test
    void encryptionWithEmptyPublicKey() {
        String publicKeyInPem = "";

        assertThrows(Exception.class, () -> new AsymEncryption(publicKeyInPem));
    }
}