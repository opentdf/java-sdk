package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.AesGcm;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Stateless parameters + operations for a pure ML-KEM (FIPS 203) algorithm
 * variant. The wire format and combiner are the bare ML-KEM KEM output run
 * through HKDF-SHA256, in contrast with {@link HybridNISTAlgorithm} (which
 * combines ML-KEM with an EC half per draft-ietf-lamps-pq-composite-kem-14).
 *
 * <h2>Wire format</h2>
 *
 * <p><b>Public key</b> ({@link #publicKeySize()} bytes inside the SPKI BIT STRING):
 * the raw ML-KEM encapsulation key, FIPS 203 encoded.
 *
 * <p><b>Private key</b> (64 bytes inside the PKCS#8 OCTET STRING):
 * the ML-KEM seed {@code (d || z)} per FIPS 203 §6.
 *
 * <p><b>Wrapped DEK envelope</b> (no ASN.1 framing — the KAS knows the
 * algorithm from the registered key, so the {@link #ciphertextSize()} prefix
 * is unambiguous):
 * <pre>mlkemCiphertext ‖ AES-GCM(nonce(12) ‖ encryptedDEK ‖ tag(16))</pre>
 *
 * <p><b>KEM combiner:</b>
 * <pre>wrapKey = HKDF-SHA256(salt = SHA-256("TDF"), ikm = mlkemSharedSecret, L = 32)</pre>
 * The 32-byte output is used directly as the AES-256 key.
 *
 * <p>The KAO field {@code type} stays {@code "wrapped"} (reuses the RSA slot;
 * the KAS disambiguates from RSA by looking up the registered key's
 * algorithm). {@code ephemeralPublicKey} is absent.
 *
 * <p>ML-KEM primitives come from BouncyCastle's low-level API — JDK 11
 * stdlib has no KEM API (added in JDK 21).
 */
public final class MLKEMAlgorithm {

    public static final MLKEMAlgorithm MLKEM_768 = new MLKEMAlgorithm(
            MLKEMParameters.ml_kem_768,
            /* publicKeySize */ 1184,
            /* ciphertextSize */ 1088,
            HybridSpki.OID_MLKEM768,
            KeyType.MLKEM768Key);

    public static final MLKEMAlgorithm MLKEM_1024 = new MLKEMAlgorithm(
            MLKEMParameters.ml_kem_1024,
            /* publicKeySize */ 1568,
            /* ciphertextSize */ 1568,
            HybridSpki.OID_MLKEM1024,
            KeyType.MLKEM1024Key);

    /** Fixed 64-byte ML-KEM seed (d || z) per FIPS 203 — same for both variants. */
    static final int SEED_SIZE = 64;

    // SecureRandom is documented thread-safe; share one instance (java:S2119).
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final MLKEMParameters mlkemParams;
    private final int publicKeySize;
    private final int ciphertextSize;
    private final ASN1ObjectIdentifier oid;
    private final KeyType keyType;

    private MLKEMAlgorithm(MLKEMParameters mlkemParams, int publicKeySize, int ciphertextSize,
                           ASN1ObjectIdentifier oid, KeyType keyType) {
        this.mlkemParams = mlkemParams;
        this.publicKeySize = publicKeySize;
        this.ciphertextSize = ciphertextSize;
        this.oid = oid;
        this.keyType = keyType;
    }

    public static MLKEMAlgorithm forKeyType(KeyType kt) {
        switch (kt) {
            case MLKEM768Key:  return MLKEM_768;
            case MLKEM1024Key: return MLKEM_1024;
            default: throw new SDKException("not an ML-KEM key type: " + kt);
        }
    }

    public int publicKeySize() { return publicKeySize; }
    public int ciphertextSize() { return ciphertextSize; }
    public KeyType keyType() { return keyType; }
    ASN1ObjectIdentifier oid() { return oid; }

    /** Generate a fresh keypair for this algorithm. */
    public MLKEMKeyPair generate() {
        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(SECURE_RANDOM, mlkemParams));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        byte[] pub = ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded();
        byte[] seed = ((MLKEMPrivateKeyParameters) kp.getPrivate()).getSeed();
        if (pub.length != publicKeySize) {
            throw new SDKException("ML-KEM public key size " + pub.length + " != expected " + publicKeySize);
        }
        if (seed.length != SEED_SIZE) {
            throw new SDKException("ML-KEM seed size " + seed.length + " != expected " + SEED_SIZE);
        }
        return new MLKEMKeyPair(this, pub, seed);
    }

    public byte[] pubKeyFromPem(String pem) {
        byte[] raw = HybridSpki.decodeSpkiPem(pem, oid);
        if (raw.length != publicKeySize) {
            throw new SDKException("invalid " + keyType + " public key size: got " + raw.length + " want " + publicKeySize);
        }
        return raw;
    }

    public byte[] privateKeyFromPem(String pem) {
        byte[] raw = HybridSpki.decodePkcs8Pem(pem, oid);
        if (raw.length != SEED_SIZE) {
            throw new SDKException("invalid " + keyType + " private key seed size: got " + raw.length + " want " + SEED_SIZE);
        }
        return raw;
    }

    /**
     * Encapsulate against {@code rawPub} (an ML-KEM encapsulation key) and AES-256-GCM
     * wrap the {@code dek}. Returns the raw wire bytes: {@code ciphertext || AES-GCM(nonce||ct||tag)}.
     * Caller base64-encodes for {@code keyAccess.wrappedKey}.
     */
    public byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != publicKeySize) {
            throw new SDKException("invalid " + keyType + " public key size: got " + rawPub.length + " want " + publicKeySize);
        }
        MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(mlkemParams, rawPub);
        SecretWithEncapsulation enc = new MLKEMGenerator(SECURE_RANDOM).generateEncapsulated(pub);
        byte[] sharedSecret = enc.getSecret();
        byte[] ciphertext = enc.getEncapsulation();
        if (ciphertext.length != ciphertextSize) {
            throw new SDKException("ML-KEM ciphertext size " + ciphertext.length + " != expected " + ciphertextSize);
        }

        byte[] wrapKey = HybridCrypto.deriveWrapKey(sharedSecret);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        byte[] out = new byte[ciphertextSize + encryptedDek.length];
        System.arraycopy(ciphertext, 0, out, 0, ciphertextSize);
        System.arraycopy(encryptedDek, 0, out, ciphertextSize, encryptedDek.length);
        return out;
    }

    /**
     * Inverse of {@link #wrapDEK(byte[], byte[])}. Used by tests and any future
     * client-side decap path; production decrypt defers to the KAS rewrap.
     */
    public byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedBlob) {
        if (rawPriv.length != SEED_SIZE) {
            throw new SDKException("invalid " + keyType + " private key seed size: got " + rawPriv.length + " want " + SEED_SIZE);
        }
        if (wrappedBlob.length <= ciphertextSize) {
            throw new SDKException(keyType + " wrapped blob too short: got " + wrappedBlob.length
                    + ", need > " + ciphertextSize);
        }
        byte[] ciphertext = Arrays.copyOfRange(wrappedBlob, 0, ciphertextSize);
        byte[] encryptedDek = Arrays.copyOfRange(wrappedBlob, ciphertextSize, wrappedBlob.length);

        MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(mlkemParams, rawPriv);
        byte[] sharedSecret = new MLKEMExtractor(priv).extractSecret(ciphertext);
        byte[] wrapKey = HybridCrypto.deriveWrapKey(sharedSecret);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }
}
