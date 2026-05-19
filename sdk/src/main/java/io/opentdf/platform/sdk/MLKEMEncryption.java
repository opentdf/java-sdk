package io.opentdf.platform.sdk;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.io.IOException;
import java.io.StringReader;
import java.security.SecureRandom;

/**
 * Handles ML-KEM-768 key encapsulation for wrapping a symmetric DEK.
 *
 * Wire format: base64(ml_kem_ciphertext [1088 bytes] || aes_gcm_wrapped_dek)
 * No ephemeralPublicKey field; KeyAccess type is "wrapped".
 */
class MLKEMEncryption {

    /** ML-KEM-768 ciphertext is always 1088 bytes. */
    static final int CIPHERTEXT_SIZE = 1088;

    private final MLKEMPublicKeyParameters publicKeyParams;

    MLKEMEncryption(String pemPublicKey) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemPublicKey));
            SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo) parser.readObject();
            parser.close();
            publicKeyParams = (MLKEMPublicKeyParameters) PublicKeyFactory.createKey(spki);
        } catch (IOException e) {
            throw new SDKException("error parsing ML-KEM-768 public key", e);
        } catch (ClassCastException e) {
            throw new SDKException("public key is not an ML-KEM key", e);
        }
    }

    /**
     * Encapsulates against the KAS ML-KEM-768 public key and AES-GCM wraps the DEK.
     *
     * @return ciphertext (1088 bytes) concatenated with the AES-GCM wrapped DEK
     */
    byte[] encapsulateAndWrap(byte[] dek) {
        MLKEMGenerator kemGen = new MLKEMGenerator(new SecureRandom());
        SecretWithEncapsulation swe = kemGen.generateEncapsulated(publicKeyParams);

        byte[] ciphertext = swe.getEncapsulation();
        byte[] sharedSecret = swe.getSecret();

        byte[] sessionKey = ECKeyPair.calculateHKDF(TDF.GLOBAL_KEY_SALT, sharedSecret);
        byte[] aesWrappedDek = new AesGcm(sessionKey).encrypt(dek).asBytes();

        byte[] combined = new byte[ciphertext.length + aesWrappedDek.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(aesWrappedDek, 0, combined, ciphertext.length, aesWrappedDek.length);
        return combined;
    }
}
