package io.opentdf.platform.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CryptoUtils {
    public static byte[] CalculateSHA256Hmac(byte[] key, byte[] data) throws NoSuchAlgorithmException,
            InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return sha256_HMAC.doFinal(data);
    }
}
