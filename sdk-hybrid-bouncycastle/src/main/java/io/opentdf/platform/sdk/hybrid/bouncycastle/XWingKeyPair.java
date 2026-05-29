package io.opentdf.platform.sdk.hybrid.bouncycastle;

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
 */
final class XWingKeyPair {

    static final String PEM_BLOCK_PUBLIC_KEY = "XWING PUBLIC KEY";
    static final String PEM_BLOCK_PRIVATE_KEY = "XWING PRIVATE KEY";

    static final int PUBLIC_KEY_SIZE = 1216;
    /** X-Wing private key is a 32-byte seed; full X25519 + ML-KEM-768 components are derived at runtime. */
    static final int PRIVATE_KEY_SIZE = 32;
    static final int CIPHERTEXT_SIZE = 1120;
    static final int SHARED_SECRET_SIZE = 32;

    private final byte[] publicKey;
    private final byte[] privateKey;

    private XWingKeyPair(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    static XWingKeyPair generate() {
        XWingKeyPairGenerator gen = new XWingKeyPairGenerator();
        gen.init(new XWingKeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        XWingPublicKeyParameters pub = (XWingPublicKeyParameters) kp.getPublic();
        XWingPrivateKeyParameters priv = (XWingPrivateKeyParameters) kp.getPrivate();
        return new XWingKeyPair(pub.getEncoded(), priv.getEncoded());
    }

    String publicKeyInPemFormat() {
        return HybridEnvelope.rawToPem(PEM_BLOCK_PUBLIC_KEY, publicKey, PUBLIC_KEY_SIZE);
    }

    String privateKeyInPemFormat() {
        return HybridEnvelope.rawToPem(PEM_BLOCK_PRIVATE_KEY, privateKey, PRIVATE_KEY_SIZE);
    }

    static byte[] pubKeyFromPem(String pem) {
        return HybridEnvelope.decodeSizedPemBlock(pem, PEM_BLOCK_PUBLIC_KEY, PUBLIC_KEY_SIZE);
    }

    static byte[] privateKeyFromPem(String pem) {
        return HybridEnvelope.decodeSizedPemBlock(pem, PEM_BLOCK_PRIVATE_KEY, PRIVATE_KEY_SIZE);
    }

    static byte[] wrapDEK(byte[] rawPub, byte[] dek) {
        if (rawPub.length != PUBLIC_KEY_SIZE) {
            throw new SDKException("invalid X-Wing public key size: got " + rawPub.length + " want " + PUBLIC_KEY_SIZE);
        }
        XWingPublicKeyParameters pub = new XWingPublicKeyParameters(rawPub);
        SecretWithEncapsulation enc = new XWingKEMGenerator(new SecureRandom()).generateEncapsulated(pub);
        byte[] sharedSecret = enc.getSecret();
        byte[] ciphertext = enc.getEncapsulation();

        byte[] wrapKey = HybridEnvelope.deriveWrapKey(sharedSecret);
        byte[] encryptedDek = new AesGcm(wrapKey).encrypt(dek).asBytes();
        return HybridEnvelope.marshalEnvelope(ciphertext, encryptedDek);
    }

    static byte[] unwrapDEK(byte[] rawPriv, byte[] wrappedDer) {
        if (rawPriv.length != PRIVATE_KEY_SIZE) {
            throw new SDKException("invalid X-Wing private key size: got " + rawPriv.length + " want " + PRIVATE_KEY_SIZE);
        }
        byte[][] parts = HybridEnvelope.unmarshalEnvelope(wrappedDer);
        byte[] ciphertext = parts[0];
        byte[] encryptedDek = parts[1];
        if (ciphertext.length != CIPHERTEXT_SIZE) {
            throw new SDKException("invalid X-Wing ciphertext size: got " + ciphertext.length + " want " + CIPHERTEXT_SIZE);
        }

        XWingPrivateKeyParameters priv = new XWingPrivateKeyParameters(rawPriv);
        byte[] sharedSecret = new XWingKEMExtractor(priv).extractSecret(ciphertext);
        byte[] wrapKey = HybridEnvelope.deriveWrapKey(sharedSecret);
        return new AesGcm(wrapKey).decrypt(new AesGcm.Encrypted(encryptedDek));
    }
}
