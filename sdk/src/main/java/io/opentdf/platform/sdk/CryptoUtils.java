package io.opentdf.platform.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Utility class for cryptographic operations such as generating RSA key pairs and calculating HMAC.
 */
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

    public static KeyPair generateECKeypair(String curveName) {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            kpg.initialize(ecSpec);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new SDKException("error creating EC keypair", e);
        }
        return kpg.generateKeyPair();
    }

    public static String getPublicKeyPEM(PublicKey publicKey) {
        return "-----BEGIN PUBLIC KEY-----\r\n" +
                Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()) +
                "\r\n-----END PUBLIC KEY-----";
    }

    public static String getPublicKeyJWK(PublicKey publicKey) {
        if ("RSA".equals(publicKey.getAlgorithm())) {
            java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
            byte[] modulusBytes = rsaPublicKey.getModulus().toByteArray();
            if (modulusBytes[0] == 0) {
                modulusBytes = java.util.Arrays.copyOfRange(modulusBytes, 1, modulusBytes.length);
            }
            byte[] exponentBytes = rsaPublicKey.getPublicExponent().toByteArray();
            if (exponentBytes[0] == 0) {
                exponentBytes = java.util.Arrays.copyOfRange(exponentBytes, 1, exponentBytes.length);
            }
            String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
            String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);
            return String.format("{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\"}", n, e);
        } else {
            throw new IllegalArgumentException("Unsupported public key algorithm: " + publicKey.getAlgorithm());
        }
    }

    public  static String getPrivateKeyPEM(PrivateKey privateKey) {
        return "-----BEGIN PRIVATE KEY-----\r\n" +
                Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()) +
                "\r\n-----END PRIVATE KEY-----";
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
