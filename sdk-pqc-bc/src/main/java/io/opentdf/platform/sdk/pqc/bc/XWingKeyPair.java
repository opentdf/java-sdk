package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.AesGcm;
import io.opentdf.platform.sdk.SDKException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

import java.security.SecureRandom;

/**
 * X-Wing (X25519 + ML-KEM-768) KEM with the ASN.1 envelope format used by TDF
 * {@code hybrid-wrapped} key access objects. Mirrors {@code lib/ocrypto/xwing.go}.
 *
 * <p>PEM is now standard SPKI/PKCS#8 with OID {@link HybridSpki#OID_XWING}
 * ({@code 1.3.6.1.4.1.62253.25722}); custom {@code XWING PUBLIC KEY} block
 * names are gone (per platform PR #3563, draft-connolly-cfrg-xwing-kem-10).
 * The raw 1216-byte public key and 32-byte private seed are unchanged —
 * they're just wrapped in SPKI/PKCS#8.
 *
 * <p>The KEM combiner is unchanged (delegated to BC's X-Wing primitive); the
 * TDF DEK wrap step still uses HKDF-SHA256 with the standard TDF salt.
 */
public final class XWingKeyPair {

    static final int PUBLIC_KEY_SIZE = 1216;
    /** X-Wing private key is a 32-byte seed; full X25519 + ML-KEM-768 components are derived at runtime. */
    static final int PRIVATE_KEY_SEED_SIZE = 32;
    static final int CIPHERTEXT_SIZE = 1120;
    static final int SHARED_SECRET_SIZE = 32;

    // SecureRandom is documented thread-safe; share one instance (java:S2119).
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final byte[] publicKey;
    private final byte[] privateKey;

    private XWingKeyPair(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static XWingKeyPair generate() {
        XWingKeyPairGenerator gen = new XWingKeyPairGenerator();
        gen.init(new XWingKeyGenerationParameters(SECURE_RANDOM));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        XWingPublicKeyParameters pub = (XWingPublicKeyParameters) kp.getPublic();
        XWingPrivateKeyParameters priv = (XWingPrivateKeyParameters) kp.getPrivate();
        return new XWingKeyPair(pub.getEncoded(), priv.getEncoded());
    }

    public String publicKeyInPemFormat() {
        return HybridSpki.encodeSpkiPem(HybridSpki.OID_XWING, publicKey);
    }

    public String privateKeyInPemFormat() {
        return HybridSpki.encodePkcs8Pem(HybridSpki.OID_XWING, privateKey);
    }

    public static byte[] pubKeyFromPem(String pem) {
        byte[] raw = HybridSpki.decodeSpkiPem(pem, HybridSpki.OID_XWING);
        if (raw.length != PUBLIC_KEY_SIZE) {
            throw new SDKException("invalid X-Wing public key size: got " + raw.length + " want " + PUBLIC_KEY_SIZE);
        }
        return raw;
    }

    public static byte[] privateKeyFromPem(String pem) {
        byte[] raw = HybridSpki.decodePkcs8Pem(pem, HybridSpki.OID_XWING);
        if (raw.length != PRIVATE_KEY_SEED_SIZE) {
            throw new SDKException("invalid X-Wing private key seed size: got " + raw.length + " want " + PRIVATE_KEY_SEED_SIZE);
        }
        return raw;
    }

    public static byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != PUBLIC_KEY_SIZE) {
            throw new SDKException("invalid X-Wing public key size: got " + rawPub.length + " want " + PUBLIC_KEY_SIZE);
        }
        XWingPublicKeyParameters pub = new XWingPublicKeyParameters(rawPub);
        SecretWithEncapsulation enc = new XWingKEMGenerator(SECURE_RANDOM).generateEncapsulated(pub);
        byte[] sharedSecret = enc.getSecret();
        byte[] ciphertext = enc.getEncapsulation();

        byte[] wrapKey = HybridCrypto.deriveWrapKey(sharedSecret);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        return HybridCrypto.marshalEnvelope(ciphertext, encryptedDek);
    }

    public static byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedDer) {
        if (rawPriv.length != PRIVATE_KEY_SEED_SIZE) {
            throw new SDKException("invalid X-Wing private key size: got " + rawPriv.length + " want " + PRIVATE_KEY_SEED_SIZE);
        }
        byte[][] parts = HybridCrypto.unmarshalEnvelope(wrappedDer);
        byte[] ciphertext = parts[0];
        byte[] encryptedDek = parts[1];
        if (ciphertext.length != CIPHERTEXT_SIZE) {
            throw new SDKException("invalid X-Wing ciphertext size: got " + ciphertext.length + " want " + CIPHERTEXT_SIZE);
        }

        XWingPrivateKeyParameters priv = new XWingPrivateKeyParameters(rawPriv);
        byte[] sharedSecret = new XWingKEMExtractor(priv).extractSecret(ciphertext);
        byte[] wrapKey = HybridCrypto.deriveWrapKey(sharedSecret);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }
}
