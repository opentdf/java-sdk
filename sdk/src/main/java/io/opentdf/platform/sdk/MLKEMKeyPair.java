package io.opentdf.platform.sdk;

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
import java.util.Base64;

/**
 * Pure ML-KEM (FIPS 203) key encapsulation for DEK wrapping.
 *
 * Wire format of the {@code wrappedKey} field (after base64 decode):
 * <pre>
 *   mlkem_ciphertext (1088 bytes for 768; 1568 for 1024)
 *   || aes_gcm_nonce (12 bytes)
 *   || aes_gcm_ciphertext_and_tag
 * </pre>
 *
 * Wrap key derivation: {@code HKDF-SHA256(ikm = mlkem_shared_secret,
 * salt = SHA-256("TDF"), info = empty, L = 32)} via
 * {@link ECKeyPair#calculateHKDF(byte[], byte[])}.
 *
 * The KAO uses {@code type == "wrapped"} (the default; no override needed)
 * and leaves {@code ephemeralPublicKey} empty — the KAS disambiguates from
 * RSA-wrapped by looking up the registered key's algorithm.
 *
 * BouncyCastle is required for the ML-KEM primitives because JDK 11 stdlib
 * has no KEM API (added in JDK 21).
 */
final class MLKEMKeyPair {

    static final MLKEMKeyPair MLKEM_768 = new MLKEMKeyPair(
            MLKEMParameters.ml_kem_768,
            "ML-KEM-768 PUBLIC KEY",
            "ML-KEM-768 PRIVATE KEY",
            /* publicKeySize */ 1184,
            /* ciphertextSize */ 1088,
            KeyType.MLKEM768Key);

    static final MLKEMKeyPair MLKEM_1024 = new MLKEMKeyPair(
            MLKEMParameters.ml_kem_1024,
            "ML-KEM-1024 PUBLIC KEY",
            "ML-KEM-1024 PRIVATE KEY",
            /* publicKeySize */ 1568,
            /* ciphertextSize */ 1568,
            KeyType.MLKEM1024Key);

    /** FIPS 203 seed (d || z) — same 64 bytes for both 768 and 1024. */
    static final int SEED_SIZE = 64;
    static final int SHARED_SECRET_SIZE = 32;

    private final MLKEMParameters mlkemParams;
    private final String pubPemBlock;
    private final String privPemBlock;
    private final int publicKeySize;
    private final int ciphertextSize;
    private final KeyType keyType;

    private final byte[] publicKey;
    private final byte[] privateKey;

    private MLKEMKeyPair(MLKEMParameters mlkemParams, String pubPemBlock, String privPemBlock,
                         int publicKeySize, int ciphertextSize, KeyType keyType) {
        this.mlkemParams = mlkemParams;
        this.pubPemBlock = pubPemBlock;
        this.privPemBlock = privPemBlock;
        this.publicKeySize = publicKeySize;
        this.ciphertextSize = ciphertextSize;
        this.keyType = keyType;
        this.publicKey = null;
        this.privateKey = null;
    }

    private MLKEMKeyPair(MLKEMKeyPair params, byte[] publicKey, byte[] privateKey) {
        this.mlkemParams = params.mlkemParams;
        this.pubPemBlock = params.pubPemBlock;
        this.privPemBlock = params.privPemBlock;
        this.publicKeySize = params.publicKeySize;
        this.ciphertextSize = params.ciphertextSize;
        this.keyType = params.keyType;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    static MLKEMKeyPair forKeyType(KeyType kt) {
        switch (kt) {
            case MLKEM768Key:  return MLKEM_768;
            case MLKEM1024Key: return MLKEM_1024;
            default: throw new SDKException("not an ML-KEM key type: " + kt);
        }
    }

    int publicKeySize() { return publicKeySize; }
    int ciphertextSize() { return ciphertextSize; }
    KeyType keyType() { return keyType; }

    MLKEMKeyPair generate() {
        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(random, mlkemParams));
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

    String publicKeyInPemFormat() {
        return rawToPem(pubPemBlock, publicKey, publicKeySize);
    }

    String privateKeyInPemFormat() {
        return rawToPem(privPemBlock, privateKey, SEED_SIZE);
    }

    byte[] getPublicKey() { return publicKey == null ? null : publicKey.clone(); }
    byte[] getPrivateKey() { return privateKey == null ? null : privateKey.clone(); }

    byte[] pubKeyFromPem(String pem) {
        return decodeSizedPemBlock(pem, pubPemBlock, publicKeySize);
    }

    byte[] privateKeyFromPem(String pem) {
        return decodeSizedPemBlock(pem, privPemBlock, SEED_SIZE);
    }

    /**
     * Encapsulate against {@code rawPub} (an ML-KEM encapsulation key) and AES-256-GCM
     * wrap the {@code dek}. Returns the raw, un-base64'd blob: ciphertext || AES-GCM(nonce||ct||tag).
     */
    byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != publicKeySize) {
            throw new SDKException("invalid " + keyType + " public key size: got " + rawPub.length + " want " + publicKeySize);
        }
        MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(mlkemParams, rawPub);
        SecretWithEncapsulation enc = new MLKEMGenerator(new SecureRandom()).generateEncapsulated(pub);
        byte[] sharedSecret = enc.getSecret();
        byte[] ciphertext = enc.getEncapsulation();
        if (ciphertext.length != ciphertextSize) {
            throw new SDKException("ML-KEM ciphertext size " + ciphertext.length + " != expected " + ciphertextSize);
        }

        byte[] wrapKey = ECKeyPair.calculateHKDF(TDF.GLOBAL_KEY_SALT, sharedSecret);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        byte[] out = new byte[ciphertextSize + encryptedDek.length];
        System.arraycopy(ciphertext, 0, out, 0, ciphertextSize);
        System.arraycopy(encryptedDek, 0, out, ciphertextSize, encryptedDek.length);
        return out;
    }

    /**
     * Inverse of {@link #wrapDEK(byte[], byte[])}. Used by unit tests and any future
     * client-side decap path; the production decrypt flow defers unwrap to the KAS.
     */
    byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedBlob) {
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
        byte[] wrapKey = ECKeyPair.calculateHKDF(TDF.GLOBAL_KEY_SALT, sharedSecret);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }

    private static String rawToPem(String blockType, byte[] raw, int expectedSize) {
        if (raw == null || raw.length != expectedSize) {
            throw new SDKException("invalid " + blockType + " size: got " + (raw == null ? -1 : raw.length)
                    + " want " + expectedSize);
        }
        String b64 = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(raw);
        return "-----BEGIN " + blockType + "-----\n" + b64 + "\n-----END " + blockType + "-----\n";
    }

    private static byte[] decodeSizedPemBlock(String pem, String expectedType, int expectedSize) {
        String header = "-----BEGIN " + expectedType + "-----";
        String footer = "-----END " + expectedType + "-----";
        int headerIdx = pem.indexOf(header);
        int footerIdx = pem.indexOf(footer);
        if (headerIdx < 0 || footerIdx < 0 || footerIdx <= headerIdx) {
            throw new SDKException("failed to parse PEM formatted " + expectedType);
        }
        String body = pem.substring(headerIdx + header.length(), footerIdx).replaceAll("\\s", "");
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new SDKException("failed to base64-decode " + expectedType + " PEM body", e);
        }
        if (raw.length != expectedSize) {
            throw new SDKException("invalid " + expectedType + " size: got " + raw.length + " want " + expectedSize);
        }
        return raw;
    }
}
