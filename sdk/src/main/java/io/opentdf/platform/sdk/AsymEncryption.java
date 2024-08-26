package io.opentdf.platform.sdk;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public class AsymEncryption {
    private final PublicKey publicKey;
    private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String PEM_HEADER = "-----BEGIN (.*)-----";
    private static final String PEM_FOOTER = "-----END (.*)-----";
    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";

    /**
     * <p>Constructor for AsymEncryption.</p>
     *
     * @param publicKeyInPem a Public Key in PEM format
     */
    public AsymEncryption(String publicKeyInPem) {

        PublicKey pubKey = null;

        String base64EncodedPem= publicKeyInPem
                .replaceAll(PEM_HEADER, "")
                .replaceAll(PEM_FOOTER, "")
                .replaceAll("\\s", "")
                .replaceAll("\r\n", "")
                .replaceAll("\n", "")
                .trim();
        

        byte[] decoded = Base64.getDecoder().decode(base64EncodedPem);

         // Check if the PEM contains a certificate
        if (publicKeyInPem.contains("BEGIN CERTIFICATE")) {
            try {
                // Parse the certificate
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
                pubKey = cert.getPublicKey();
            } catch (CertificateException e) {
                throw new SDKException("x509.ParseCertificate failed: " + e.getMessage(), e);
            }
        } else {
            // Otherwise, treat it as a PKIX public key
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("RSA is not a valid algorithm!!!???!!!", e);
            }
            try {
                pubKey = keyFactory.generatePublic(spec);
            } catch (InvalidKeySpecException e) {
                throw new SDKException("error creating asymmetric encryption", e);
            }
        }

        // Check if the public key is RSA
        if (pubKey instanceof java.security.interfaces.RSAPublicKey) {
            this.publicKey = pubKey;
        } else {
            throw new SDKException("Not an RSA PEM formatted public key");
        }
    }

    public AsymEncryption(PublicKey publicKey) {
       this.publicKey = Objects.requireNonNull(publicKey);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param data the data to encrypt
     * @return the encrypted data
     */
    public byte[] encrypt(byte[] data) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SDKException("error getting instance of cipher during encryption", e);
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        } catch (InvalidKeyException e) {
            throw new SDKException("error encrypting with private key", e);
        }
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new SDKException("error performing encryption", e);
        }
    }

    /**
     * <p>publicKeyInPemFormat.</p>
     * @return the public key in PEM format
     */
    public String publicKeyInPemFormat() throws Exception {
        String publicKeyPem = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
        return PUBLIC_KEY_HEADER + '\n' + publicKeyPem + '\n' + PUBLIC_KEY_FOOTER + '\n';
    }
}