package io.opentdf.platform.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class CryptoUtils {
    private static final int KEYPAIR_SIZE = 2048;

    public static byte[] CalculateSHA256Hmac(byte[] key, byte[] data) {
        Mac sha256_HMAC = null;
        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error getting instance of hash", e);
        }
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        try {
            sha256_HMAC.init(secret_key);
        } catch (InvalidKeyException e) {
            throw new SDKException("error creating hash", e);
        }

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

    public static String getRSAPrivateKeyPEM(PrivateKey privateKey) {
        if (!"RSA".equals(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("can't get private key PEM for algorithm [" + privateKey.getAlgorithm() + "]");
        }

        return "-----BEGIN PRIVATE KEY-----\r\n" +
                Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()) +
                "\r\n-----END PRIVATE KEY-----";
    }


}
