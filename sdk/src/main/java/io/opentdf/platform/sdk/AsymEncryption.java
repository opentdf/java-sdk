package io.opentdf.platform.sdk;


import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymEncryption {
    private PublicKey publicKey;

    public AsymEncryption(String publicKeyInPem) throws Exception {
        publicKeyInPem = publicKeyInPem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyInPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.publicKey = kf.generatePublic(spec);
    }

    public byte[] encrypt(byte[] data) throws Exception {
        if (this.publicKey == null) {
            throw new Exception("Failed to encrypt, public key is empty");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        return cipher.doFinal(data);
    }

    public String publicKeyInPemFormat() throws Exception {
        if (this.publicKey == null) {
            throw new Exception("Failed to generate PEM formatted public key");
        }

        String publicKeyPem = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + publicKeyPem + "\n-----END PUBLIC KEY-----\n";
    }
}