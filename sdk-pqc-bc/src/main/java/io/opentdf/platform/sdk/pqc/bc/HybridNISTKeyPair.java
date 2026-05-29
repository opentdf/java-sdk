package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.AesGcm;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * NIST hybrid post-quantum key wrapping (P-256 + ML-KEM-768 and P-384 + ML-KEM-1024).
 *
 * Wire layout of the wrapped DEK:
 * <pre>
 *   SEQUENCE {
 *     [0] IMPLICIT OCTET STRING hybridCiphertext  -- ephemeralECPoint || mlkemCiphertext
 *     [1] IMPLICIT OCTET STRING encryptedDEK      -- AES-256-GCM(iv||ct||tag)
 *   }
 * </pre>
 * with {@code wrapKey = HKDF-SHA256(ecdhSecret || mlkemSecret, salt = SHA-256("TDF"))}.
 *
 * Raw key encoding:
 * <ul>
 *   <li>Public key: {@code uncompressedECPoint || mlkemEncapsulationKey}</li>
 *   <li>Private key: {@code paddedECScalar || mlkemSeed(64B)}</li>
 * </ul>
 *
 * EC operations use only stdlib JCA. ML-KEM operations use BouncyCastle's
 * low-level API because no JDK 11 stdlib KEM API exists (added in JDK 21).
 */
public final class HybridNISTKeyPair {

    public static final HybridNISTKeyPair P256_MLKEM768 = new HybridNISTKeyPair(
            "secp256r1",
            /* ecPubSize */ 65,
            /* ecPrivSize */ 32,
            /* mlkemPubSize */ 1184,
            /* mlkemCtSize */ 1088,
            MLKEMParameters.ml_kem_768,
            "SECP256R1 MLKEM768 PUBLIC KEY",
            "SECP256R1 MLKEM768 PRIVATE KEY",
            KeyType.HybridSecp256r1MLKEM768Key);

    public static final HybridNISTKeyPair P384_MLKEM1024 = new HybridNISTKeyPair(
            "secp384r1",
            /* ecPubSize */ 97,
            /* ecPrivSize */ 48,
            /* mlkemPubSize */ 1568,
            /* mlkemCtSize */ 1568,
            MLKEMParameters.ml_kem_1024,
            "SECP384R1 MLKEM1024 PUBLIC KEY",
            "SECP384R1 MLKEM1024 PRIVATE KEY",
            KeyType.HybridSecp384r1MLKEM1024Key);

    /** Fixed 64-byte ML-KEM seed (d || z) per FIPS 203. */
    static final int MLKEM_SEED_SIZE = 64;

    private final String curveName;
    private final int ecPubSize;
    private final int ecPrivSize;
    private final int mlkemPubSize;
    private final int mlkemCtSize;
    private final MLKEMParameters mlkemParams;
    private final String pubPemBlock;
    private final String privPemBlock;
    private final KeyType keyType;
    private final ECParameterSpec ecParams;
    private final int ecFieldByteSize;

    private final byte[] publicKey;
    private final byte[] privateKey;

    private HybridNISTKeyPair(String curveName, int ecPubSize, int ecPrivSize, int mlkemPubSize, int mlkemCtSize,
                              MLKEMParameters mlkemParams, String pubPemBlock, String privPemBlock, KeyType keyType) {
        this.curveName = curveName;
        this.ecPubSize = ecPubSize;
        this.ecPrivSize = ecPrivSize;
        this.mlkemPubSize = mlkemPubSize;
        this.mlkemCtSize = mlkemCtSize;
        this.mlkemParams = mlkemParams;
        this.pubPemBlock = pubPemBlock;
        this.privPemBlock = privPemBlock;
        this.keyType = keyType;
        this.ecParams = ecParamsFor(curveName);
        this.ecFieldByteSize = (this.ecParams.getCurve().getField().getFieldSize() + 7) / 8;
        this.publicKey = null;
        this.privateKey = null;
    }

    private HybridNISTKeyPair(HybridNISTKeyPair params, byte[] publicKey, byte[] privateKey) {
        this.curveName = params.curveName;
        this.ecPubSize = params.ecPubSize;
        this.ecPrivSize = params.ecPrivSize;
        this.mlkemPubSize = params.mlkemPubSize;
        this.mlkemCtSize = params.mlkemCtSize;
        this.mlkemParams = params.mlkemParams;
        this.pubPemBlock = params.pubPemBlock;
        this.privPemBlock = params.privPemBlock;
        this.keyType = params.keyType;
        this.ecParams = params.ecParams;
        this.ecFieldByteSize = params.ecFieldByteSize;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    int publicKeySize() { return ecPubSize + mlkemPubSize; }
    int privateKeySize() { return ecPrivSize + MLKEM_SEED_SIZE; }
    int ciphertextSize() { return ecPubSize + mlkemCtSize; }
    KeyType keyType() { return keyType; }

    public HybridNISTKeyPair generate() {
        SecureRandom random = new SecureRandom();

        // EC half — stdlib KeyPairGenerator gives us scalar + point in one call.
        EcKeypairBytes ec = generateEcKeypairBytes(random);

        // ML-KEM half — BC's low-level API; no JDK 11 stdlib alternative.
        MLKEMKeyPairGenerator mlGen = new MLKEMKeyPairGenerator();
        mlGen.init(new MLKEMKeyGenerationParameters(random, mlkemParams));
        AsymmetricCipherKeyPair mkp = mlGen.generateKeyPair();
        byte[] mlPubBytes = ((MLKEMPublicKeyParameters) mkp.getPublic()).getEncoded();
        byte[] mlSeed = ((MLKEMPrivateKeyParameters) mkp.getPrivate()).getSeed();

        if (mlPubBytes.length != mlkemPubSize) {
            throw new SDKException("ML-KEM public key size " + mlPubBytes.length + " != expected " + mlkemPubSize);
        }
        if (mlSeed.length != MLKEM_SEED_SIZE) {
            throw new SDKException("ML-KEM seed size " + mlSeed.length + " != expected " + MLKEM_SEED_SIZE);
        }

        byte[] pub = concat(ec.publicPoint, mlPubBytes);
        byte[] priv = concat(ec.scalar, mlSeed);
        return new HybridNISTKeyPair(this, pub, priv);
    }

    public String publicKeyInPemFormat() {
        return HybridCrypto.rawToPem(pubPemBlock, publicKey, publicKeySize());
    }

    public String privateKeyInPemFormat() {
        return HybridCrypto.rawToPem(privPemBlock, privateKey, privateKeySize());
    }

    public byte[] getPublicKey() { return publicKey == null ? null : publicKey.clone(); }
    public byte[] getPrivateKey() { return privateKey == null ? null : privateKey.clone(); }

    public byte[] pubKeyFromPem(String pem) {
        return HybridCrypto.decodeSizedPemBlock(pem, pubPemBlock, publicKeySize());
    }

    public byte[] privateKeyFromPem(String pem) {
        return HybridCrypto.decodeSizedPemBlock(pem, privPemBlock, privateKeySize());
    }

    public byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != publicKeySize()) {
            throw new SDKException("invalid " + keyType + " public key size: got " + rawPub.length + " want " + publicKeySize());
        }
        byte[] recipientEcPub = Arrays.copyOfRange(rawPub, 0, ecPubSize);
        byte[] recipientMlPub = Arrays.copyOfRange(rawPub, ecPubSize, rawPub.length);

        SecureRandom random = new SecureRandom();

        // ECDH: generate ephemeral keypair, compute shared secret, ship the ephemeral point.
        EcKeypairBytes ephemeral = generateEcKeypairBytes(random);
        BigInteger ephemeralScalar = new BigInteger(1, ephemeral.scalar);
        byte[] ecdhSecret = computeEcdhSecret(ephemeralScalar, recipientEcPub);

        // ML-KEM encapsulate.
        MLKEMPublicKeyParameters mlPub = new MLKEMPublicKeyParameters(mlkemParams, recipientMlPub);
        SecretWithEncapsulation kemEnc = new MLKEMGenerator(random).generateEncapsulated(mlPub);
        byte[] mlSecret = kemEnc.getSecret();
        byte[] mlCiphertext = kemEnc.getEncapsulation();
        if (mlCiphertext.length != mlkemCtSize) {
            throw new SDKException("ML-KEM ciphertext size " + mlCiphertext.length + " != expected " + mlkemCtSize);
        }

        byte[] combinedSecret = concat(ecdhSecret, mlSecret);
        byte[] hybridCt = concat(ephemeral.publicPoint, mlCiphertext);
        byte[] wrapKey = HybridCrypto.deriveWrapKey(combinedSecret);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        return HybridCrypto.marshalEnvelope(hybridCt, encryptedDek);
    }

    public byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedDer) {
        if (rawPriv.length != privateKeySize()) {
            throw new SDKException("invalid " + keyType + " private key size: got " + rawPriv.length + " want " + privateKeySize());
        }
        byte[][] parts = HybridCrypto.unmarshalEnvelope(wrappedDer);
        byte[] hybridCt = parts[0];
        byte[] encryptedDek = parts[1];
        if (hybridCt.length != ciphertextSize()) {
            throw new SDKException("invalid " + keyType + " ciphertext size: got " + hybridCt.length + " want " + ciphertextSize());
        }

        byte[] ephemeralEcPub = Arrays.copyOfRange(hybridCt, 0, ecPubSize);
        byte[] mlCiphertext = Arrays.copyOfRange(hybridCt, ecPubSize, hybridCt.length);

        byte[] ecScalarBytes = Arrays.copyOfRange(rawPriv, 0, ecPrivSize);
        byte[] mlSeed = Arrays.copyOfRange(rawPriv, ecPrivSize, rawPriv.length);

        BigInteger ecScalar = new BigInteger(1, ecScalarBytes);
        byte[] ecdhSecret = computeEcdhSecret(ecScalar, ephemeralEcPub);

        MLKEMPrivateKeyParameters mlPriv = new MLKEMPrivateKeyParameters(mlkemParams, mlSeed);
        byte[] mlSecret = new MLKEMExtractor(mlPriv).extractSecret(mlCiphertext);

        byte[] combinedSecret = concat(ecdhSecret, mlSecret);
        byte[] wrapKey = HybridCrypto.deriveWrapKey(combinedSecret);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }

    /** Resolve a named-curve {@link ECParameterSpec} via stdlib JCA. */
    private static ECParameterSpec ecParamsFor(String curveName) {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(curveName));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new SDKException("EC parameters not available for curve " + curveName, e);
        }
    }

    /**
     * Generate an EC keypair via stdlib and return scalar (padded) and uncompressed-point bytes.
     */
    private EcKeypairBytes generateEcKeypairBytes(SecureRandom random) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(curveName), random);
            KeyPair kp = kpg.generateKeyPair();
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            byte[] scalar = toFixedLength(priv.getS(), ecPrivSize);
            byte[] point = encodeUncompressedPoint(pub.getW(), ecFieldByteSize);
            if (point.length != ecPubSize) {
                throw new SDKException("encoded EC point size " + point.length + " != expected " + ecPubSize);
            }
            return new EcKeypairBytes(scalar, point);
        } catch (Exception e) {
            throw new SDKException("failed to generate EC keypair on " + curveName, e);
        }
    }

    /** Standard ECDH via JCA: x-coordinate of {@code scalar * peerPoint}, fixed-size big-endian. */
    private byte[] computeEcdhSecret(BigInteger scalar, byte[] peerUncompressedPoint) {
        try {
            ECPoint peerPoint = decodeUncompressedPoint(peerUncompressedPoint, ecFieldByteSize);
            ECPublicKeySpec peerSpec = new ECPublicKeySpec(peerPoint, ecParams);
            ECPrivateKeySpec mySpec = new ECPrivateKeySpec(scalar, ecParams);
            KeyFactory kf = KeyFactory.getInstance("EC");

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kf.generatePrivate(mySpec));
            ka.doPhase(kf.generatePublic(peerSpec), /* lastPhase */ true);
            byte[] raw = ka.generateSecret();
            // JCA may strip leading zeros; left-pad to the field size to match Go's crypto/ecdh ECDH output.
            if (raw.length != ecFieldByteSize) {
                raw = leftPad(raw, ecFieldByteSize);
            }
            return raw;
        } catch (Exception e) {
            throw new SDKException("ECDH failed for " + curveName, e);
        }
    }

    private static byte[] encodeUncompressedPoint(ECPoint w, int byteSize) {
        byte[] x = toFixedLength(w.getAffineX(), byteSize);
        byte[] y = toFixedLength(w.getAffineY(), byteSize);
        byte[] out = new byte[1 + 2 * byteSize];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, byteSize);
        System.arraycopy(y, 0, out, 1 + byteSize, byteSize);
        return out;
    }

    private static ECPoint decodeUncompressedPoint(byte[] encoded, int byteSize) {
        if (encoded.length != 1 + 2 * byteSize || encoded[0] != 0x04) {
            throw new SDKException("invalid uncompressed EC point encoding (length=" + encoded.length
                    + ", lead=0x" + Integer.toHexString(encoded[0] & 0xFF) + ")");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 1 + byteSize));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 1 + byteSize, 1 + 2 * byteSize));
        return new ECPoint(x, y);
    }

    /** Convert a non-negative {@link BigInteger} to a fixed-length big-endian byte array. */
    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) return bytes;
        if (bytes.length > length) {
            int excess = bytes.length - length;
            for (int i = 0; i < excess; i++) {
                if (bytes[i] != 0) {
                    throw new SDKException("value too large for width " + length);
                }
            }
            return Arrays.copyOfRange(bytes, excess, bytes.length);
        }
        byte[] out = new byte[length];
        System.arraycopy(bytes, 0, out, length - bytes.length, bytes.length);
        return out;
    }

    private static byte[] leftPad(byte[] src, int width) {
        if (src.length >= width) return src;
        byte[] out = new byte[width];
        System.arraycopy(src, 0, out, width - src.length, src.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static final class EcKeypairBytes {
        final byte[] scalar;
        final byte[] publicPoint;
        EcKeypairBytes(byte[] scalar, byte[] publicPoint) {
            this.scalar = scalar;
            this.publicPoint = publicPoint;
        }
    }
}
