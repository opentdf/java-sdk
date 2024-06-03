package io.opentdf.platform.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Array;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CryptoUtils {
    private static final int KEYPAIR_SIZE = 2048;

    public static byte[] CalculateSHA256Hmac(byte[] key, byte[] data) throws NoSuchAlgorithmException,
            InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return sha256_HMAC.doFinal(data);
    }

    public static byte[] concat(byte[] ...arrays) {
        var totalSize = Arrays.stream(arrays).map(Array::getLength).reduce(0, Integer::sum);
        var concatted = new byte[totalSize];
        var pos = 0;
        for (var array: arrays) {
            System.arraycopy(array, 0, concatted, pos, array.length);
            pos += array.length;
        }
        return concatted;
    }

    public static byte[][] split(byte[] toSplit, int ...indexes) {
        var prevIdx = 0;
        var idxs = Stream.concat(Arrays.stream(indexes).boxed(), Stream.of(toSplit.length)).toArray(Integer[]::new);
        var out = new byte[idxs.length][];
        for (int i = 0; i < idxs.length; i++) {
            var idx = idxs[i];
            var arr = new byte[idx - prevIdx];
            System.arraycopy(toSplit, prevIdx, arr, 0, arr.length);
            out[i] = arr;
            assert(prevIdx <= idx);
            prevIdx = idx;
        }

        return out;
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
