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

    void encryptionWithValidCert() throws Exception {
        String certInPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIC/TCCAeWgAwIBAgIUXW8s3YqpfBwH/obH1WWCyxum+dUwDQYJKoZIhvcNAQEL\n" +
                "BQAwDjEMMAoGA1UEAwwDa2FzMB4XDTI0MDgyNjE1NTk1OVoXDTI1MDgyNjE1NTk1\n" +
                "OVowDjEMMAoGA1UEAwwDa2FzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
                "AQEAqoOoHEG22LwxB/9A0OG0ZTizzqjUgNpOBj/z31ynmCI5fJR+bEoAp8fEVa3t\n" +
                "8Z9EEMi103u+SCtqG0nsh5A5EZOkEQIJA7f4LxAzo4vcpKAzIDagVat/C7FbkZ2j\n" +
                "oqPRWfiXw4WdrsYOT3Ty//ZREqA7VCS2WJ58wvBvAduAd/URKqCrQlA2atmmT49A\n" +
                "224xz1Ghl67uQQK7+SWdh9AKF2SW3p5fqTutPBvNf9jrh5yfE60QRxQQ2VfdQMRG\n" +
                "Nl0hSfDs7J6l15xzJYivHpaq3jx5EsAoqcnr5tE4vqOdOziOomd9Rlfn2iuiL5BF\n" +
                "EMLpa70rjWbI5chxJ09LI86avQIDAQABo1MwUTAdBgNVHQ4EFgQU3k3anh79M5M0\n" +
                "oTI7W4yhPJi9ZhswHwYDVR0jBBgwFoAU3k3anh79M5M0oTI7W4yhPJi9ZhswDwYD\n" +
                "VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADvFBvHAfxkVL13sQ+sz+\n" +
                "UnrHjekh9Jm85f1cFbSNjTfTgQ9z8xyWMLdlIhLFk9pOoFxBETi24vm7q/RTH/SX\n" +
                "UmB53iV0XyydMqG5SUu7qR0yh3DXc8SdMbMduWXGYr0r8IIYUamcxnRmV+L08bLa\n" +
                "kae3VLyPF5CiwuxWR/ixnM4SrxwkB/RrqxFjmpkzlZbqgyW8ISVnQFy3eUkAfM1b\n" +
                "OcL/UAwQ2pXmfEFjYBs5mDEpKwGC0DxW4tg0FIsb3bbAvqy8ETklExkOh0VfJP4a\n" +
                "CMz9WjmCfS15t0mPzofK8ir20kF0u0sWvviVVlun+8KYdFOG/wzS100cPNn/wqug\n" +
                "4w==\n" +
                "-----END CERTIFICATE-----";;
        AsymEncryption asymEncryption = new AsymEncryption(certInPem);
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