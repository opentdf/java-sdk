package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.AesGcm;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
 * Stateless parameters + operations for a NIST hybrid PQC algorithm
 * (P-256 + ML-KEM-768 or P-384 + ML-KEM-1024). Conforms to
 * {@code draft-ietf-lamps-pq-composite-kem-14}.
 *
 * <h2>Wire format</h2>
 *
 * <p><b>Public key</b> ({@link #publicKeySize()} bytes inside the SPKI BIT STRING):
 * <pre>mlkemEncapsulationKey ‖ ecPointUncompressed</pre>
 *
 * <p><b>Private key</b> (variable length inside the PKCS#8 OCTET STRING):
 * <pre>mlkemSeed(64) ‖ ECPrivateKey(RFC 5915 DER)</pre>
 *
 * <p><b>Hybrid ciphertext</b> ({@link #ciphertextSize()} bytes, payload of the
 * outer TDF ASN.1 envelope's first OCTET STRING):
 * <pre>mlkemCiphertext ‖ ephemeralECPointUncompressed</pre>
 *
 * <p><b>KEM combiner (per draft-14 §4.3):</b>
 * <pre>wrapKey = SHA3-256(mlkemSS ‖ tradSS ‖ tradCT ‖ tradPK ‖ Label)</pre>
 * where {@code tradSS} is the ECDH shared secret (x-coordinate, left-padded
 * to the curve's field size), {@code tradCT} is the ephemeral EC public key
 * (uncompressed), {@code tradPK} is the recipient's EC public key
 * (uncompressed), and {@code Label} is the scheme-specific ASCII string
 * (e.g. {@code "MLKEM768-P256"}). The 32-byte SHA3-256 output is used
 * directly as the AES-256 wrap key — no HKDF step.
 *
 * <p>The outer TDF DEK envelope (ASN.1 {@code SEQUENCE { [0] OCTET STRING, [1]
 * OCTET STRING }}) is unchanged.
 *
 * <p>EC operations use stdlib JCA. ML-KEM operations use BouncyCastle's
 * low-level API.
 */
public final class HybridNISTAlgorithm {

    public static final HybridNISTAlgorithm P256_MLKEM768 = new HybridNISTAlgorithm(
            "secp256r1",
            /* ecPubSize */ 65,
            /* ecPrivSize */ 32,
            /* mlkemPubSize */ 1184,
            /* mlkemCtSize */ 1088,
            MLKEMParameters.ml_kem_768,
            HybridSpki.OID_P256_MLKEM768,
            "MLKEM768-P256",
            KeyType.HybridSecp256r1MLKEM768Key);

    public static final HybridNISTAlgorithm P384_MLKEM1024 = new HybridNISTAlgorithm(
            "secp384r1",
            /* ecPubSize */ 97,
            /* ecPrivSize */ 48,
            /* mlkemPubSize */ 1568,
            /* mlkemCtSize */ 1568,
            MLKEMParameters.ml_kem_1024,
            HybridSpki.OID_P384_MLKEM1024,
            "MLKEM1024-P384",
            KeyType.HybridSecp384r1MLKEM1024Key);

    /** Fixed 64-byte ML-KEM seed (d || z) per FIPS 203. */
    static final int MLKEM_SEED_SIZE = 64;

    // SecureRandom is documented thread-safe; a single shared instance avoids the
    // per-call seeding cost and silences SonarCloud java:S2119.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String curveName;
    private final int ecPubSize;
    private final int ecPrivSize;
    private final int mlkemPubSize;
    private final int mlkemCtSize;
    private final MLKEMParameters mlkemParams;
    private final ASN1ObjectIdentifier oid;
    private final byte[] label;
    private final KeyType keyType;
    private final ECParameterSpec ecParams;
    private final int ecFieldByteSize;
    private final int ecOrderBitLength;

    private HybridNISTAlgorithm(String curveName, int ecPubSize, int ecPrivSize, int mlkemPubSize, int mlkemCtSize,
                                MLKEMParameters mlkemParams, ASN1ObjectIdentifier oid, String labelAscii,
                                KeyType keyType) {
        this.curveName = curveName;
        this.ecPubSize = ecPubSize;
        this.ecPrivSize = ecPrivSize;
        this.mlkemPubSize = mlkemPubSize;
        this.mlkemCtSize = mlkemCtSize;
        this.mlkemParams = mlkemParams;
        this.oid = oid;
        this.label = labelAscii.getBytes(StandardCharsets.US_ASCII);
        this.keyType = keyType;
        this.ecParams = ecParamsFor(curveName);
        this.ecFieldByteSize = (this.ecParams.getCurve().getField().getFieldSize() + 7) / 8;
        this.ecOrderBitLength = this.ecParams.getOrder().bitLength();
    }

    public int publicKeySize() { return mlkemPubSize + ecPubSize; }
    public int ciphertextSize() { return mlkemCtSize + ecPubSize; }
    public KeyType keyType() { return keyType; }
    ASN1ObjectIdentifier oid() { return oid; }

    /** Generate a fresh keypair for this algorithm. */
    public HybridNISTKeyPair generate() {
        // EC half — stdlib KeyPairGenerator gives us scalar + point in one call.
        EcKeypairBytes ec = generateEcKeypairBytes(SECURE_RANDOM);

        // ML-KEM half — BC's low-level API; no JDK 11 stdlib alternative.
        MLKEMKeyPairGenerator mlGen = new MLKEMKeyPairGenerator();
        mlGen.init(new MLKEMKeyGenerationParameters(SECURE_RANDOM, mlkemParams));
        AsymmetricCipherKeyPair mkp = mlGen.generateKeyPair();
        byte[] mlPubBytes = ((MLKEMPublicKeyParameters) mkp.getPublic()).getEncoded();
        byte[] mlSeed = ((MLKEMPrivateKeyParameters) mkp.getPrivate()).getSeed();

        if (mlPubBytes.length != mlkemPubSize) {
            throw new SDKException("ML-KEM public key size " + mlPubBytes.length + " != expected " + mlkemPubSize);
        }
        if (mlSeed.length != MLKEM_SEED_SIZE) {
            throw new SDKException("ML-KEM seed size " + mlSeed.length + " != expected " + MLKEM_SEED_SIZE);
        }

        // draft-14: public key = mlkemPK || ecPoint;  private key = mlkemSeed || ECPrivateKey(DER)
        byte[] pub = HybridCrypto.concat(mlPubBytes, ec.publicPoint);
        byte[] ecScalarDer = HybridSpki.encodeEcPrivateKey(new BigInteger(1, ec.scalar), ecOrderBitLength);
        byte[] priv = HybridCrypto.concat(mlSeed, ecScalarDer);
        return new HybridNISTKeyPair(this, pub, priv);
    }

    public byte[] pubKeyFromPem(String pem) {
        byte[] raw = HybridSpki.decodeSpkiPem(pem, oid);
        if (raw.length != publicKeySize()) {
            throw new SDKException("invalid " + keyType + " public key size: got " + raw.length + " want " + publicKeySize());
        }
        return raw;
    }

    public byte[] privateKeyFromPem(String pem) {
        byte[] raw = HybridSpki.decodePkcs8Pem(pem, oid);
        if (raw.length <= MLKEM_SEED_SIZE) {
            throw new SDKException("invalid " + keyType + " private key: " + raw.length
                    + " bytes, need > " + MLKEM_SEED_SIZE + " (mlkemSeed || ECPrivateKey)");
        }
        return raw;
    }

    public byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != publicKeySize()) {
            throw new SDKException("invalid " + keyType + " public key size: got " + rawPub.length + " want " + publicKeySize());
        }
        // draft-14 split: mlkemPK || ecPoint
        byte[] recipientMlPub = Arrays.copyOfRange(rawPub, 0, mlkemPubSize);
        byte[] recipientEcPub = Arrays.copyOfRange(rawPub, mlkemPubSize, rawPub.length);

        // ECDH: generate ephemeral keypair, compute shared secret, ship the ephemeral point.
        EcKeypairBytes ephemeral = generateEcKeypairBytes(SECURE_RANDOM);
        BigInteger ephemeralScalar = new BigInteger(1, ephemeral.scalar);
        byte[] tradSS = computeEcdhSecret(ephemeralScalar, recipientEcPub);
        byte[] tradCT = ephemeral.publicPoint;       // ephemeral EC pub (the KEM ciphertext)
        byte[] tradPK = recipientEcPub;              // recipient's static EC pub

        // ML-KEM encapsulate.
        MLKEMPublicKeyParameters mlPub = new MLKEMPublicKeyParameters(mlkemParams, recipientMlPub);
        SecretWithEncapsulation kemEnc = new MLKEMGenerator(SECURE_RANDOM).generateEncapsulated(mlPub);
        byte[] mlSS = kemEnc.getSecret();
        byte[] mlCT = kemEnc.getEncapsulation();
        if (mlCT.length != mlkemCtSize) {
            throw new SDKException("ML-KEM ciphertext size " + mlCT.length + " != expected " + mlkemCtSize);
        }

        // draft-14 split: ciphertext = mlkemCT || ephemeralECPoint
        byte[] hybridCt = HybridCrypto.concat(mlCT, tradCT);
        byte[] wrapKey = deriveDraft14WrapKey(mlSS, tradSS, tradCT, tradPK);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        return HybridCrypto.marshalEnvelope(hybridCt, encryptedDek);
    }

    public byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedDer) {
        if (rawPriv.length <= MLKEM_SEED_SIZE) {
            throw new SDKException("invalid " + keyType + " private key: " + rawPriv.length
                    + " bytes, need > " + MLKEM_SEED_SIZE + " (mlkemSeed || ECPrivateKey)");
        }
        byte[][] parts = HybridCrypto.unmarshalEnvelope(wrappedDer);
        byte[] hybridCt = parts[0];
        byte[] encryptedDek = parts[1];
        if (hybridCt.length != ciphertextSize()) {
            throw new SDKException("invalid " + keyType + " ciphertext size: got " + hybridCt.length + " want " + ciphertextSize());
        }

        // draft-14 split: ciphertext = mlkemCT || ephemeralECPoint
        byte[] mlCT = Arrays.copyOfRange(hybridCt, 0, mlkemCtSize);
        byte[] tradCT = Arrays.copyOfRange(hybridCt, mlkemCtSize, hybridCt.length);

        // draft-14 split: private key = mlkemSeed || ECPrivateKey(DER)
        byte[] mlSeed = Arrays.copyOfRange(rawPriv, 0, MLKEM_SEED_SIZE);
        byte[] ecPrivateKeyDer = Arrays.copyOfRange(rawPriv, MLKEM_SEED_SIZE, rawPriv.length);
        BigInteger ecScalar = HybridSpki.decodeEcPrivateKey(ecPrivateKeyDer);

        byte[] tradSS = computeEcdhSecret(ecScalar, tradCT);

        MLKEMPrivateKeyParameters mlPriv = new MLKEMPrivateKeyParameters(mlkemParams, mlSeed);
        byte[] mlSS = new MLKEMExtractor(mlPriv).extractSecret(mlCT);

        // To derive the wrap key we need tradPK (recipient's EC pub) too. Recover it from
        // the EC scalar by multiplying with the curve generator and emitting the
        // uncompressed point. The stdlib KeyPairGenerator path doesn't expose scalar*G
        // directly, but ECDH against the generator yields just the x-coordinate; the
        // simplest correct path is to derive the public point via KeyFactory + the
        // generated curve params.
        byte[] tradPK = derivePublicPointBytes(ecScalar);
        byte[] wrapKey = deriveDraft14WrapKey(mlSS, tradSS, tradCT, tradPK);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }

    /**
     * draft-ietf-lamps-pq-composite-kem-14 §4.3 combiner:
     * {@code SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)}.
     * The 32-byte output is used directly as an AES-256 key — no HKDF.
     */
    private byte[] deriveDraft14WrapKey(byte[] mlkemSS, byte[] tradSS, byte[] tradCT, byte[] tradPK) {
        try {
            MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
            sha3.update(mlkemSS);
            sha3.update(tradSS);
            sha3.update(tradCT);
            sha3.update(tradPK);
            sha3.update(label);
            return sha3.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("SHA3-256 not available", e);
        }
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

    /** Generate an EC keypair via stdlib and return scalar (padded) and uncompressed-point bytes. */
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

    /**
     * Recover an EC public point from a private scalar and emit it as uncompressed-point bytes.
     * Used during unwrap to reconstruct {@code tradPK} for the draft-14 combiner — the recipient's
     * static EC pub is not on the wire.
     *
     * <p>Uses BouncyCastle's {@link org.bouncycastle.math.ec.ECPoint#multiply} which is
     * constant-time (window-NAF over a Montgomery-laddered fixed-base table). This matters
     * because we're operating on a private scalar on the unwrap path — a naive double-and-add
     * would leak the scalar's Hamming weight via instruction timing.
     */
    private byte[] derivePublicPointBytes(BigInteger scalar) {
        try {
            ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec(curveName);
            org.bouncycastle.math.ec.ECPoint q = bcSpec.getG().multiply(scalar).normalize();
            BigInteger x = q.getAffineXCoord().toBigInteger();
            BigInteger y = q.getAffineYCoord().toBigInteger();
            return encodeUncompressedPoint(new ECPoint(x, y), ecFieldByteSize);
        } catch (Exception e) {
            throw new SDKException("failed to recover EC public point on " + curveName, e);
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

    private static final class EcKeypairBytes {
        final byte[] scalar;
        final byte[] publicPoint;
        EcKeypairBytes(byte[] scalar, byte[] publicPoint) {
            this.scalar = scalar;
            this.publicPoint = publicPoint;
        }
    }
}
