package io.opentdf.platform.sdk;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public class ECKeyPair {

    private static final int SHA256_BYTES = 32;
    private static final String EC_ALGORITHM = "EC";

    private final ECCurve curve;

    public enum ECAlgorithm {
        ECDH,
        ECDSA
    }

    private KeyPair keyPair;

    public ECKeyPair() {
        this(ECCurve.SECP256R1);
    }

    public ECKeyPair(ECCurve curve) {
        this.curve = Objects.requireNonNull(curve);
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(EC_ALGORITHM);
            generator.initialize(new ECGenParameterSpec(this.curve.getCurveName()));
            this.keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    static ECPublicKey publicKeyFromPem(String pem) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String pemData = pem.replaceAll("-----(BEGIN|END) [A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pemData);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(der));
    }

    public ECPublicKey getPublicKey() {
        return (ECPublicKey) this.keyPair.getPublic();
    }

    public ECPrivateKey getPrivateKey() {
        return (ECPrivateKey) this.keyPair.getPrivate();
    }

    ECCurve getCurve() {
        return this.curve;
    }

    public String publicKeyInPEMFormat() {
        return toPem("PUBLIC KEY", this.keyPair.getPublic().getEncoded());
    }

    public String privateKeyInPEMFormat() {
        return toPem("PRIVATE KEY", this.keyPair.getPrivate().getEncoded());
    }

    public int keySize() {
        return this.keyPair.getPrivate().getEncoded().length * 8;
    }

    public byte[] compressECPublickey() {
        return encodeCompressedPoint((ECPublicKey) this.keyPair.getPublic());
    }

    public static byte[] computeECDHKey(ECPublicKey publicKey, ECPrivateKey privateKey) {
        try {
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH");
            aKeyAgree.init(privateKey);
            aKeyAgree.doPhase(publicKey, true);
            return aKeyAgree.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a HKDF key derived from the provided salt and secret
     * that is 32 bytes (256 bits) long.
     */
    public static byte[] calculateHKDF(byte[] salt, byte[] secret) {
        try {
            // RFC 5869: if salt is absent, substitute a zero-filled buffer of Hash output size.
            byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[SHA256_BYTES] : salt;
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
            byte[] prk = hmac.doFinal(secret);

            // HKDF-Expand with empty info and L = 32 (a single HMAC block).
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            hmac.update((byte) 0x01);
            return hmac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] computeECDSASig(byte[] data, ECPrivateKey privateKey) {
        try {
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(digest);
            return ecdsaSign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static Boolean verifyECDSAig(byte[] digest, byte[] signature, ECPublicKey publicKey) {
        try {
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(digest);
            return ecdsaVerify.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toPem(String type, byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    private static byte[] encodeCompressedPoint(ECPublicKey publicKey) {
        ECPoint w = publicKey.getW();
        ECParameterSpec params = publicKey.getParams();
        int size = (params.getCurve().getField().getFieldSize() + 7) / 8;
        byte[] x = toFixedLength(w.getAffineX(), size);
        byte[] result = new byte[size + 1];
        result[0] = (byte) (w.getAffineY().testBit(0) ? 0x03 : 0x02);
        System.arraycopy(x, 0, result, 1, size);
        return result;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] result = new byte[length];
        if (bytes.length > length) {
            // BigInteger.toByteArray() may prepend a zero sign byte; strip it.
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        } else {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        }
        return result;
    }
}
