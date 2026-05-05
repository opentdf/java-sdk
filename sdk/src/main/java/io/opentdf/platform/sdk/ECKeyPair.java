package io.opentdf.platform.sdk;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.*;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.KeyAgreement;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Objects;
// https://www.bouncycastle.org/latest_releases.html

public class ECKeyPair {

    private static final int SHA256_BYTES = 32;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final ECCurve curve;

    public enum ECAlgorithm {
        ECDH,
        ECDSA
    }

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    private KeyPair keyPair;

    public ECKeyPair() {
        this(ECCurve.SECP256R1, ECAlgorithm.ECDH);
    }

    public ECKeyPair(ECCurve curve, ECAlgorithm algorithm) {
        this.curve = Objects.requireNonNull(curve);
        KeyPairGenerator generator;

        try {
            // Should this just use the algorithm vs use ECDH only for ECDH and ECDSA for
            // everything else.
            if (algorithm == ECAlgorithm.ECDH) {
                generator = KeyPairGeneratorSpi.getInstance(ECAlgorithm.ECDH.name());
            } else {
                generator = KeyPairGeneratorSpi.getInstance(ECAlgorithm.ECDSA.name());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        ECGenParameterSpec spec = new ECGenParameterSpec(this.curve.getCurveName());
        try {
            generator.initialize(spec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        this.keyPair = generator.generateKeyPair();
    }

    public ECPublicKey getPublicKey() {
        return (ECPublicKey) this.keyPair.getPublic();
    }

    public ECPrivateKey getPrivateKey() {
        return (ECPrivateKey) this.keyPair.getPrivate();
    }

    ECCurve getCurve() {
        return this.curve;
    }

    public String publicKeyInPEMFormat() {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);

        try {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", this.keyPair.getPublic().getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return writer.toString();
    }

    public String privateKeyInPEMFormat() {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);

        try {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", this.keyPair.getPrivate().getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return writer.toString();
    }

    public int keySize() {
        return this.keyPair.getPrivate().getEncoded().length * 8;
    }

    public byte[] compressECPublickey() {
        return getCompressedECPublicKey(this.keyPair.getPublic());
    }

    private static byte[] getCompressedECPublicKey(PublicKey publicKey) {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X962Parameters params = X962Parameters.getInstance(publicKeyInfo.getAlgorithm().getParameters());
        if (params.isImplicitlyCA()) {
            throw new IllegalArgumentException("Implicitly CA parameters are not supported.");
        }

        org.bouncycastle.math.ec.ECCurve bcCurve =
                ECNamedCurveTable.getByOID((ASN1ObjectIdentifier) params.getParameters()).getCurve();
        org.bouncycastle.math.ec.ECPoint p =
                bcCurve.decodePoint(publicKeyInfo.getPublicKeyData().getOctets());

        return new X9ECPoint(p, true).getPointEncoding();
    }

    public static String getPEMPublicKeyFromX509Cert(String pemInX509Format) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemInX509Format));
            X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) parser.readObject();
            parser.close();
            SubjectPublicKeyInfo publicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);
            ECPublicKey publicKey = null;
            try {
                publicKey = (ECPublicKey) converter.getPublicKey(publicKeyInfo);
            } catch (PEMException e) {
                throw new RuntimeException(e);
            }

            // EC public key to pem formated.
            StringWriter writer = new StringWriter();
            PemWriter pemWriter = new PemWriter(writer);

            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
            return writer.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] compressECPublickey(String pemECPubKey) {
        try {
            KeyFactory ecKeyFac = KeyFactory.getInstance("EC");
            PemReader pemReader = new PemReader(new StringReader(pemECPubKey));
            PemObject pemObject = pemReader.readPemObject();
            PublicKey pubKey = ecKeyFac.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
            return getCompressedECPublicKey(pubKey);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static String publicKeyFromECPoint(byte[] ecPoint, String curveName) {
        try {
            org.bouncycastle.math.ec.ECPoint point =
                    ECNamedCurveTable.getByName(curveName).getCurve().decodePoint(ecPoint);
            java.security.spec.ECPoint jpoint = new java.security.spec.ECPoint(
                    point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());

            // Create EC Public key
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);

            ECPublicKeySpec spec = new ECPublicKeySpec(jpoint, ecParameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            // EC Public key to pem format.
            StringWriter writer = new StringWriter();
            PemWriter pemWriter = new PemWriter(writer);
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
            return writer.toString();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException | InvalidParameterSpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPublicKey publicKeyFromPem(String pemEncoding) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemEncoding));
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) parser.readObject();
            parser.close();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return (ECPublicKey) converter.getPublicKey(publicKeyInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPrivateKey privateKeyFromPem(String pemEncoding) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemEncoding));
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) parser.readObject();
            parser.close();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return (ECPrivateKey) converter.getPrivateKey(privateKeyInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] computeECDHKey(ECPublicKey publicKey, ECPrivateKey privateKey) {
        try {
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH");
            aKeyAgree.init(privateKey);
            aKeyAgree.doPhase(publicKey, true);
            return aKeyAgree.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a HKDF key derived from the provided salt and secret
     * that is 32 bytes (256 bits) long.
     */
    public static byte[] calculateHKDF(byte[] salt, byte[] secret) {
        byte[] key = new byte[SHA256_BYTES];
        HKDFParameters params = new HKDFParameters(secret, salt, null);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(SHA256Digest.newInstance());
        hkdf.init(params);
        hkdf.generateBytes(key, 0, key.length);
        return key;
    }

    public static byte[] computeECDSASig(byte[] digest, ECPrivateKey privateKey) {
        try {
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(digest);
            return ecdsaSign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static Boolean verifyECDSAig(byte[] digest, byte[] signature, ECPublicKey publicKey) {
        try {
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(digest);
            return ecdsaVerify.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
