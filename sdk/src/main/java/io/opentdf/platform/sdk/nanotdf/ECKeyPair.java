package io.opentdf.platform.sdk.nanotdf;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.*;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.jce.spec.ECPublicKeySpec;


import javax.crypto.KeyAgreement;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
// https://www.bouncycastle.org/latest_releases.html

public class ECKeyPair {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public enum ECAlgorithm {
        ECDH,
        ECDSA
    }

    public enum NanoTDFECCurve {
        SECP256R1("secp256r1"),
        PRIME256V1("prime256v1"),
        SECP384R1("secp384r1"),
        SECP521R1("secp521r1");

        private String name;

        NanoTDFECCurve(String curveName) {
            this.name = curveName;
        }

        @Override
        public String toString() {
            return name;
        }
    }
    private KeyPair keyPair;
    private String curveName;

    public ECKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        this("secp256r1", ECAlgorithm.ECDH);
    }

    public ECKeyPair(String curveName, ECAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchProviderException {
        KeyPairGenerator generator;
        if (algorithm == ECAlgorithm.ECDH) {
            generator = KeyPairGenerator.getInstance("ECDH", "BC");
        } else {
            generator = KeyPairGenerator.getInstance("ECDSA", "BC");
        }

        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        generator.initialize(spec);
        this.keyPair = generator.generateKeyPair();
        this.curveName = curveName;
    }

    public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey, String curveName) {
        this.keyPair = new KeyPair(publicKey, privateKey);
        this.curveName = curveName;
    }

    public ECPublicKey getPublicKey() {
        return (ECPublicKey)this.keyPair.getPublic();
    }

    public ECPrivateKey getPrivateKey() {
        return (ECPrivateKey)this.keyPair.getPrivate();
    }

    public static int getECKeySize(String curveName) {
        if (curveName.equalsIgnoreCase(NanoTDFECCurve.SECP256R1.toString()) ||
                curveName.equalsIgnoreCase(NanoTDFECCurve.PRIME256V1.toString())) {
            return 32;
        } else if (curveName.equalsIgnoreCase(NanoTDFECCurve.SECP384R1.toString())) {
            return 48;
        } else if (curveName.equalsIgnoreCase(NanoTDFECCurve.SECP521R1.toString())) {
            return 66;
        } else {
            throw new IllegalArgumentException("Unsupported ECC algorithm.");
        }
    }

    public String publicKeyInPEMFormat() throws IOException {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", this.keyPair.getPublic().getEncoded()));
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public String privateKeyInPEMFormat() throws IOException {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PRIVATE KEY", this.keyPair.getPrivate().getEncoded()));
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public int keySize() {
        return this.keyPair.getPrivate().getEncoded().length * 8;
    }

    public String curveName() {
        return this.curveName = curveName;
    }

    public  byte[] compressECPublickey() {
        return ((ECPublicKey)this.keyPair.getPublic()).getQ().getEncoded(true);
    }

    public static String getPEMPublicKeyFromX509Cert(String pemInX509Format) throws CertificateException, IOException {
        PEMParser parser = new PEMParser(new StringReader(pemInX509Format));
        X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) parser.readObject();
        parser.close();
        SubjectPublicKeyInfo publicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        ECPublicKey publicKey = (ECPublicKey)converter.getPublicKey(publicKeyInfo);

        // EC public key to pem formated.
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public static byte[] compressECPublickey(String pemECPubKey) throws NoSuchAlgorithmException,
            IOException, InvalidKeySpecException, NoSuchProviderException {
        KeyFactory ecKeyFac = KeyFactory.getInstance("EC", "BC");
        PemReader pemReader = new PemReader(new StringReader(pemECPubKey));
        PemObject pemObject = pemReader.readPemObject();
        PublicKey pubKey = ecKeyFac.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
        return ((ECPublicKey)pubKey).getQ().getEncoded(true);
    }

    public static String publicKeyFromECPoint(byte[] ecPoint, String curveName) throws InvalidKeySpecException,
            NoSuchAlgorithmException, NoSuchProviderException, IOException {

        // Create EC Public key
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        ECPoint point = ecSpec.getCurve().decodePoint(ecPoint);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // EC Public keu to pem format.
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public static ECPublicKey publicKeyFromPem(String pemEncoding) throws IOException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));
        SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) parser.readObject();
        parser.close();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return (ECPublicKey) converter.getPublicKey(publicKeyInfo);
    }

    public static ECPrivateKey privateKeyFromPem(String pemEncoding)
            throws IOException, CertificateException
    {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo)parser.readObject();
        parser.close();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return (ECPrivateKey) converter.getPrivateKey(privateKeyInfo);
    }

    public static byte[] computeECDHKey(ECPublicKey publicKey, ECPrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        aKeyAgree.init(privateKey);
        aKeyAgree.doPhase(publicKey, true);
        return aKeyAgree.generateSecret();
    }

    public static byte[] calculateHKDF(byte[] salt, byte[] secret) {
        byte[] key = new byte[secret.length];
        HKDFParameters params = new HKDFParameters(secret, salt, null);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(SHA256Digest.newInstance());
        hkdf.init(params);
        hkdf.generateBytes(key, 0, key.length);
        return key;
    }

    public static byte[] computeECDSASig(byte[] digest, ECPrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(digest);
        return ecdsaSign.sign();
    }

    public static Boolean verifyECDSAig(byte[] digest, byte[] signature, ECPublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(digest);
        return ecdsaVerify.verify(signature);
    }
}