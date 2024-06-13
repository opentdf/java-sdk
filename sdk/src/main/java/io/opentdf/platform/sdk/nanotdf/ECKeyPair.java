package io.opentdf.platform.sdk.nanotdf;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMException;
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

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

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

    public ECKeyPair() {
        this("secp256r1", ECAlgorithm.ECDH);
    }

    public ECKeyPair(String curveName, ECAlgorithm algorithm) {
        KeyPairGenerator generator;

        try {
            // Should this just use the algorithm vs use ECDH only for ECDH and ECDSA for everything else.
            if (algorithm == ECAlgorithm.ECDH) {
                generator = KeyPairGeneratorSpi.getInstance(ECAlgorithm.ECDH.name(), BOUNCY_CASTLE_PROVIDER);
            } else {
                generator = KeyPairGeneratorSpi.getInstance(ECAlgorithm.ECDSA.name(), BOUNCY_CASTLE_PROVIDER);
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

    public String publicKeyInPEMFormat()  {
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

    public String curveName() {
        return this.curveName = curveName;
    }

    public  byte[] compressECPublickey() {
        return ((ECPublicKey)this.keyPair.getPublic()).getQ().getEncoded(true);
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
                publicKey = (ECPublicKey)converter.getPublicKey(publicKeyInfo);
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
            KeyFactory ecKeyFac = KeyFactory.getInstance("EC", "BC");
            PemReader pemReader = new PemReader(new StringReader(pemECPubKey));
            PemObject pemObject = pemReader.readPemObject();
            PublicKey pubKey = ecKeyFac.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
            return ((ECPublicKey)pubKey).getQ().getEncoded(true);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }  catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static String publicKeyFromECPoint(byte[] ecPoint, String curveName)  {
        try {
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
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPublicKey publicKeyFromPem(String pemEncoding) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemEncoding));
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) parser.readObject();
            parser.close();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);
            return (ECPublicKey) converter.getPublicKey(publicKeyInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECPrivateKey privateKeyFromPem(String pemEncoding) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemEncoding));
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo)parser.readObject();
            parser.close();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER);;
            return (ECPrivateKey) converter.getPrivateKey(privateKeyInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] computeECDHKey(ECPublicKey publicKey, ECPrivateKey privateKey) {
        try {
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
            aKeyAgree.init(privateKey);
            aKeyAgree.doPhase(publicKey, true);
            return aKeyAgree.generateSecret();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
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
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(digest);
            return ecdsaSign.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }  catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static Boolean verifyECDSAig(byte[] digest, byte[] signature, ECPublicKey publicKey) {
        try {
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(digest);
            return ecdsaVerify.verify(signature);
        }  catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }  catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}