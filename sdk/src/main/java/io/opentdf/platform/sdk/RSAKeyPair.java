package io.opentdf.platform.sdk;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Set;

public class RSAKeyPair {
    final static int KEY_LENGTH = 2048;
    private static final KeyPairGenerator generator;
    public static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    static {
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("can't create RSA keys for some reason", e);
        }
        generator.initialize(KEY_LENGTH);
    }

    final private RSAPublicKey rsaPublicKey;
    final private RSAPrivateKey rsaPrivateKey;

    RSAKeyPair(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey) {
        this.rsaPublicKey = rsaPublicKey;
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public String toPEM() {
        var der = this.rsaPublicKey.getEncoded();
        var encoder = Base64.getMimeEncoder(64, new byte[]{'\n'});
        return "-----BEGIN PUBLIC KEY-----\n" + encoder.encodeToString(der) + "\n-----END PUBLIC KEY-----";
    }

    public RSAKey toRSAKey() {
        return new RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyUse(KeyUse.SIGNATURE)
                .build();
    }

    public RSAKeyPair() {
        var keypair = generator.generateKeyPair();
        this.rsaPrivateKey = (RSAPrivateKey) keypair.getPrivate();
        this.rsaPublicKey = (RSAPublicKey) keypair.getPublic();
    }

    /**
     * <p>encrypt.</p>
     *
     * @param data the data to encrypt
     * @return the encrypted data
     */
    public byte[] encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            return cipher.doFinal(data);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new SDKException("error performing encryption", e);
        }
    }

    /**
     * <p>decrypt.</p>
     *
     * @param data the data to decrypt
     * @return the decrypted data
     */
    public byte[] decrypt(byte[] data) {
        try {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        return cipher.doFinal(data);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            throw new SDKException("error performing decryption", e);
        }
    }
}
