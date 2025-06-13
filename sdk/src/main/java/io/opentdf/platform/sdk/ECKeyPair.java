package io.opentdf.platform.sdk;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.util.ECKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.util.io.pem.*;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.KeyAgreement;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.io.*;
import java.security.*;
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
        SECP256R1("secp256r1", KeyType.EC256Key),
        PRIME256V1("prime256v1", KeyType.EC256Key),
        SECP384R1("secp384r1", KeyType.EC384Key),
        SECP521R1("secp521r1", KeyType.EC521Key);

        private String name;
        private KeyType keyType;

        NanoTDFECCurve(String curveName, KeyType keyType) {
            this.name = curveName;
            this.keyType = keyType;
        }

        @Override
        public String toString() {
            return name;
        }

        public KeyType getKeyType() {
            return keyType;
        }
    }

    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;
    private final String curveName;

    public ECKeyPair() {
        this("secp256r1", ECAlgorithm.ECDH);
    }

    public ECKeyPair(String curveName, ECAlgorithm algorithm) {
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

        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        try {
            generator.initialize(spec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        KeyPair keyPair = generator.generateKeyPair();
        this.publicKey = (ECPublicKey)keyPair.getPublic();
        this.privateKey = (ECPrivateKey)keyPair.getPrivate();
        this.curveName = curveName;
    }

    public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey, String curveName) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.curveName = curveName;
    }

    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }

    public ECPrivateKey getPrivateKey() {
        return this.privateKey;
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

    public String publicKeyInPEMFormat() {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);

        try {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
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
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return writer.toString();
    }

    public int keySize() {
        return privateKey.getEncoded().length * 8;
    }

    public String curveName() {
        return this.curveName;
    }

    public byte[] compressECPublickey() {
        return getCompressedECPublicKey(publicKey);
    }

    private static byte[] getCompressedECPublicKey(PublicKey publicKey) {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X962Parameters params = X962Parameters.getInstance(publicKeyInfo.getAlgorithm().getParameters());
        if (params.isImplicitlyCA()) {
            throw new IllegalArgumentException("Implicitly CA parameters are not supported.");
        }

        ECCurve curve = ECNamedCurveTable.getByOID((ASN1ObjectIdentifier)params.getParameters()).getCurve();
        ECPoint p = curve.decodePoint(publicKeyInfo.getPublicKeyData().getOctets());

        return new X9ECPoint(p, true).getPointEncoding();
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
            ECPoint point = ECNamedCurveTable.getByName(curveName).getCurve().decodePoint(ecPoint);
            java.security.spec.ECPoint jpoint = new java.security.spec.ECPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());

            // Create EC Public key
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);

            ECPublicKeySpec spec = new ECPublicKeySpec(jpoint, ecParameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            // EC Public keu to pem format.
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

    public static byte[] calculateHKDF(byte[] salt, byte[] secret) {
        byte[] key = new byte[secret.length];
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