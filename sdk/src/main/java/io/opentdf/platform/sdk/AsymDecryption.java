package io.opentdf.platform.sdk;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AsymDecryption {
    private PrivateKey privateKey;

    public AsymDecryption(String privateKeyInPem) throws Exception {
        String privateKeyPEM = privateKeyInPem
                .replace("-----BEGIN PRIVATE KEY-----\n", "")
                .replace("-----END PRIVATE KEY-----\n", "")
                .replaceAll("\\s", ""); // remove whitespaces

        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(spec);
    }

    public byte[] decrypt(byte[] data) throws Exception {
        if (this.privateKey == null) {
            throw new Exception("Failed to decrypt, private key is empty");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        return cipher.doFinal(data);
    }
}