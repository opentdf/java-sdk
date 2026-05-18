package io.opentdf.platform.sdk;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * NIST hybrid post-quantum key wrapping (P-256 + ML-KEM-768 and P-384 + ML-KEM-1024).
 * Mirrors {@code lib/ocrypto/hybrid_nist.go}.
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
 */
final class HybridNISTKeyPair {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static final HybridNISTKeyPair P256_MLKEM768 = new HybridNISTKeyPair(
            "secp256r1",
            /* ecPubSize */ 65,
            /* ecPrivSize */ 32,
            /* mlkemPubSize */ 1184,
            /* mlkemCtSize */ 1088,
            MLKEMParameters.ml_kem_768,
            "SECP256R1 MLKEM768 PUBLIC KEY",
            "SECP256R1 MLKEM768 PRIVATE KEY",
            KeyType.HybridSecp256r1MLKEM768Key);

    static final HybridNISTKeyPair P384_MLKEM1024 = new HybridNISTKeyPair(
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
    private final ECNamedCurveParameterSpec curveSpec;

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
        this.curveSpec = ECNamedCurveTable.getParameterSpec(curveName);
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
        this.curveSpec = params.curveSpec;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    int publicKeySize() { return ecPubSize + mlkemPubSize; }
    int privateKeySize() { return ecPrivSize + MLKEM_SEED_SIZE; }
    int ciphertextSize() { return ecPubSize + mlkemCtSize; }
    KeyType keyType() { return keyType; }

    HybridNISTKeyPair generate() {
        SecureRandom random = new SecureRandom();

        // EC half — generate ephemeral scalar, derive uncompressed point.
        BigInteger ecScalar = generateEcScalar(random);
        ECPoint ecPoint = curveSpec.getG().multiply(ecScalar).normalize();
        byte[] ecPubBytes = ecPoint.getEncoded(/* compressed */ false);
        byte[] ecPrivBytes = leftPad(ecScalar.toByteArray(), ecPrivSize);

        // ML-KEM half.
        MLKEMKeyPairGenerator mlGen = new MLKEMKeyPairGenerator();
        mlGen.init(new MLKEMKeyGenerationParameters(random, mlkemParams));
        AsymmetricCipherKeyPair mkp = mlGen.generateKeyPair();
        byte[] mlPubBytes = ((MLKEMPublicKeyParameters) mkp.getPublic()).getEncoded();
        byte[] mlSeed = ((MLKEMPrivateKeyParameters) mkp.getPrivate()).getSeed();

        if (ecPubBytes.length != ecPubSize) {
            throw new SDKException("EC public key size " + ecPubBytes.length + " != expected " + ecPubSize);
        }
        if (mlPubBytes.length != mlkemPubSize) {
            throw new SDKException("ML-KEM public key size " + mlPubBytes.length + " != expected " + mlkemPubSize);
        }
        if (mlSeed.length != MLKEM_SEED_SIZE) {
            throw new SDKException("ML-KEM seed size " + mlSeed.length + " != expected " + MLKEM_SEED_SIZE);
        }

        byte[] pub = concat(ecPubBytes, mlPubBytes);
        byte[] priv = concat(ecPrivBytes, mlSeed);
        return new HybridNISTKeyPair(this, pub, priv);
    }

    String publicKeyInPemFormat() {
        return HybridCrypto.rawToPem(pubPemBlock, publicKey, publicKeySize());
    }

    String privateKeyInPemFormat() {
        return HybridCrypto.rawToPem(privPemBlock, privateKey, privateKeySize());
    }

    byte[] getPublicKey() { return publicKey == null ? null : publicKey.clone(); }
    byte[] getPrivateKey() { return privateKey == null ? null : privateKey.clone(); }

    byte[] pubKeyFromPem(String pem) {
        return HybridCrypto.decodeSizedPemBlock(pem, pubPemBlock, publicKeySize());
    }

    byte[] privateKeyFromPem(String pem) {
        return HybridCrypto.decodeSizedPemBlock(pem, privPemBlock, privateKeySize());
    }

    byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != publicKeySize()) {
            throw new SDKException("invalid " + keyType + " public key size: got " + rawPub.length + " want " + publicKeySize());
        }
        byte[] recipientEcPub = Arrays.copyOfRange(rawPub, 0, ecPubSize);
        byte[] recipientMlPub = Arrays.copyOfRange(rawPub, ecPubSize, rawPub.length);

        SecureRandom random = new SecureRandom();

        // ECDH: generate ephemeral, compute shared secret, capture ephemeral point.
        BigInteger ephemeralScalar = generateEcScalar(random);
        byte[] ephemeralEcPub = curveSpec.getG().multiply(ephemeralScalar).normalize().getEncoded(false);
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
        byte[] hybridCt = concat(ephemeralEcPub, mlCiphertext);
        byte[] wrapKey = HybridCrypto.deriveWrapKey(combinedSecret, null, null);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        return HybridCrypto.marshalEnvelope(hybridCt, encryptedDek);
    }

    byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedDer) {
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
        byte[] wrapKey = HybridCrypto.deriveWrapKey(combinedSecret, null, null);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }

    /** Generate a uniformly random scalar in [1, n-1] using rejection sampling. */
    private BigInteger generateEcScalar(SecureRandom random) {
        BigInteger n = curveSpec.getN();
        int nBitLength = n.bitLength();
        BigInteger d;
        do {
            d = new BigInteger(nBitLength, random);
        } while (d.signum() <= 0 || d.compareTo(n) >= 0);
        return d;
    }

    /** Standard ECDH: x-coordinate of {@code scalar * peerPoint}, fixed-size big-endian. */
    private byte[] computeEcdhSecret(BigInteger scalar, byte[] peerUncompressedPoint) {
        try {
            ECPoint peer = curveSpec.getCurve().decodePoint(peerUncompressedPoint);
            ECPublicKeySpec peerSpec = new ECPublicKeySpec(peer, curveSpec);
            ECPrivateKeySpec mySpec = new ECPrivateKeySpec(scalar, curveSpec);
            KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey peerPub = kf.generatePublic(peerSpec);
            PrivateKey myPriv = kf.generatePrivate(mySpec);

            KeyAgreement ka = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
            ka.init(myPriv);
            ka.doPhase(peerPub, /* lastPhase */ true);
            byte[] raw = ka.generateSecret();
            // JCA may strip leading zeros; left-pad to the field size to match Go's crypto/ecdh ECDH output.
            if (raw.length != ecPrivSize) {
                raw = leftPad(raw, ecPrivSize);
            }
            return raw;
        } catch (Exception e) {
            throw new SDKException("ECDH failed for " + curveName, e);
        }
    }

    private static byte[] leftPad(byte[] src, int width) {
        if (src.length == width) return src;
        if (src.length > width) {
            // Strip leading 0x00 sign byte from BigInteger.toByteArray() if present.
            int excess = src.length - width;
            for (int i = 0; i < excess; i++) {
                if (src[i] != 0) {
                    throw new SDKException("scalar/secret too large for width " + width);
                }
            }
            return Arrays.copyOfRange(src, excess, src.length);
        }
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
}
