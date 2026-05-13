package io.opentdf.platform.sdk;

import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.GeneralSecurityException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * PEM / X.509 helpers used only by tests. Uses standard java.security APIs so
 * the SDK does not require BouncyCastle on the test classpath either.
 */
final class PemTestUtils {
    private PemTestUtils() {
    }

    static ECPublicKey publicKeyFromPem(String pemEncoding) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(decodePem(pemEncoding)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static ECPrivateKey privateKeyFromPem(String pemEncoding) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decodePem(pemEncoding)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static String getPEMPublicKeyFromX509Cert(String pemInX509Format) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pemInX509Format.getBytes(StandardCharsets.UTF_8)));
            return encodePem("PUBLIC KEY", cert.getPublicKey().getEncoded());
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] compressECPublickey(String pemECPubKey) {
        ECPublicKey publicKey = publicKeyFromPem(pemECPubKey);
        ECParameterSpec params = publicKey.getParams();
        int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
        ECPoint w = publicKey.getW();
        byte[] x = toFixedLength(w.getAffineX(), fieldSize);
        byte[] out = new byte[1 + fieldSize];
        out[0] = (byte) (w.getAffineY().testBit(0) ? 0x03 : 0x02);
        System.arraycopy(x, 0, out, 1, fieldSize);
        return out;
    }

    static String publicKeyFromECPoint(byte[] ecPoint, String curveName) {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(curveName));
            ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
            ECPoint w = decodePoint(ecPoint, params.getCurve());
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey publicKey = kf.generatePublic(new ECPublicKeySpec(w, params));
            return encodePem("PUBLIC KEY", publicKey.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static ECPoint decodePoint(byte[] data, EllipticCurve curve) {
        int fieldSize = (curve.getField().getFieldSize() + 7) / 8;
        if (data.length == 0) {
            throw new IllegalArgumentException("empty EC point");
        }
        int prefix = data[0] & 0xff;
        if (prefix == 0x04 && data.length == 1 + 2 * fieldSize) {
            BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(data, 1, 1 + fieldSize));
            BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(data, 1 + fieldSize, data.length));
            return new ECPoint(x, y);
        }
        if ((prefix == 0x02 || prefix == 0x03) && data.length == 1 + fieldSize) {
            BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(data, 1, 1 + fieldSize));
            BigInteger y = getY(curve, x, prefix);
            return new ECPoint(x, y);
        }
        throw new IllegalArgumentException("unsupported EC point encoding: prefix=0x"
                + Integer.toHexString(prefix) + ", length=" + data.length);
    }

    private static @NonNull BigInteger getY(EllipticCurve curve, BigInteger x, int prefix) {
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        // y^2 = x^3 + a*x + b (mod p); valid for all NIST P-curves we support.
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
                .add(curve.getA().multiply(x))
                .add(curve.getB())
                .mod(p);
        // NIST P-curves all have p ≡ 3 (mod 4), so √rhs = rhs^((p+1)/4) mod p.
        if (!p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
            throw new IllegalArgumentException("point decompression only supports curves with p mod 4 == 3");
        }
        BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        boolean wantOdd = (prefix == 0x03);
        if (y.testBit(0) != wantOdd) {
            y = p.subtract(y);
        }
        return y;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] result = new byte[length];
        if (bytes.length > length) {
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        } else {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        }
        return result;
    }

    private static byte[] decodePem(String pem) {
        String body = pem.replaceAll("-----(BEGIN|END) [A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static String encodePem(String type, byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }
}
