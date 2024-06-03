package io.opentdf.platform.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public class CryptoUtils {
    private static final int KEYPAIR_SIZE = 2048;

    public static byte[] CalculateSHA256Hmac(byte[] key, byte[] data) throws NoSuchAlgorithmException,
            InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return sha256_HMAC.doFinal(data);
    }

    public static KeyPair generateRSAKeypair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error creating keypair", e);
        }
        kpg.initialize(KEYPAIR_SIZE);
        return kpg.generateKeyPair();
    }

    public static String getRSAPublicKeyPEM(PublicKey publicKey) {
        if (!"RSA".equals(publicKey.getAlgorithm())) {
            throw new IllegalArgumentException("can't get public key PEM for algorithm [" + publicKey.getAlgorithm() + "]");
        }

        return "-----BEGIN PUBLIC KEY-----\r\n" +
                Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()) +
                "\r\n-----END PUBLIC KEY-----";
    }
}
