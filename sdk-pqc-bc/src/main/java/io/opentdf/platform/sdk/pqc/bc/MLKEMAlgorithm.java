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

/**
 * Stateless parameters + operations for a pure ML-KEM (FIPS 203) algorithm
 * variant. Conforms to opentdf/platform PR #3562 (the open replacement for the
 * closed PR #3491). The wire envelope is the same ASN.1 SEQUENCE the hybrid
 * PQC path uses; the only thing that differs from {@link HybridNISTAlgorithm}
 * is the AES wrap-key derivation — see {@link #wrapDEK(byte[], byte[])} below.
 *
 * <h2>Wire format</h2>
 *
 * <p><b>Public key</b> ({@link #publicKeySize()} bytes inside the SPKI BIT STRING):
 * the raw ML-KEM encapsulation key, FIPS 203 encoded.
 *
 * <p><b>Private key</b> (64 bytes inside the PKCS#8 OCTET STRING):
 * the ML-KEM seed {@code (d || z)} per FIPS 203 §6.
 *
 * <p><b>Wrapped DEK envelope</b> — same ASN.1 SEQUENCE as
 * {@link HybridCrypto#marshalEnvelope(byte[], byte[])}:
 * <pre>SEQUENCE { [0] IMPLICIT OCTET STRING mlkemCiphertext,
 *            [1] IMPLICIT OCTET STRING AES-GCM(iv(12) ‖ DEK ‖ tag(16)) }</pre>
 *
 * <p><b>AES-256 wrap key:</b> the 32-byte ML-KEM Decaps shared secret is used
 * <i>directly</i> as the AES key — <b>no HKDF</b>. Rationale (per platform ADR
 * {@code adr/decisions/2026-06-16-mlkem-direct-key-wrap.md}): HSM-backed KAS
 * providers (Thales Luna T-Series firmware 7.15.1, strict-FIPS) can only emit
 * the Decaps output as a non-extractable {@code CKK_AES} object, so an HKDF
 * step would block HSM unwrap. FIPS 203 §6.3/§7.3 guarantees the Decaps
 * output is a uniformly-random 32-byte string; HKDF would not add entropy.
 * The {@code "mlkem-wrapped"} KAO type itself is the domain-separation tag
 * HKDF's {@code info} would have provided. Hybrid PQC schemes still need HKDF
 * because there the KDF is the combiner for the two shared-secret halves.
 *
 * <p>The KAO field {@code type} is {@code "mlkem-wrapped"} (its own scheme —
 * distinct from {@code "wrapped"} which RSA uses and {@code "hybrid-wrapped"}
 * which the hybrid schemes use). {@code ephemeralPublicKey} is absent.
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
     * wrap the {@code dek} using the Decaps shared secret directly (no HKDF). Returns
     * the ASN.1 envelope bytes; caller base64-encodes for {@code keyAccess.wrappedKey}.
     */
    public byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != publicKeySize) {
            throw new SDKException("invalid " + keyType + " public key size: got " + rawPub.length + " want " + publicKeySize);
        }
        MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(mlkemParams, rawPub);
        SecretWithEncapsulation enc = new MLKEMGenerator(SECURE_RANDOM).generateEncapsulated(pub);
        byte[] wrapKey = enc.getSecret();           // 32-byte AES key, used directly (no HKDF)
        byte[] ciphertext = enc.getEncapsulation();
        if (ciphertext.length != ciphertextSize) {
            throw new SDKException("ML-KEM ciphertext size " + ciphertext.length + " != expected " + ciphertextSize);
        }
        if (wrapKey.length != HybridCrypto.WRAP_KEY_SIZE) {
            throw new SDKException("ML-KEM shared secret size " + wrapKey.length
                    + " != expected " + HybridCrypto.WRAP_KEY_SIZE);
        }
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        return HybridCrypto.marshalEnvelope(ciphertext, encryptedDek);
    }

    /**
     * Inverse of {@link #wrapDEK(byte[], byte[])}. Used by tests and any future
     * client-side decap path; production decrypt defers to the KAS rewrap.
     */
    public byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedDer) {
        if (rawPriv.length != SEED_SIZE) {
            throw new SDKException("invalid " + keyType + " private key seed size: got " + rawPriv.length + " want " + SEED_SIZE);
        }
        byte[][] parts = HybridCrypto.unmarshalEnvelope(wrappedDer);
        byte[] ciphertext = parts[0];
        byte[] encryptedDek = parts[1];
        if (ciphertext.length != ciphertextSize) {
            throw new SDKException("invalid " + keyType + " ciphertext size: got " + ciphertext.length + " want " + ciphertextSize);
        }

        MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(mlkemParams, rawPriv);
        byte[] wrapKey = new MLKEMExtractor(priv).extractSecret(ciphertext);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }
}
