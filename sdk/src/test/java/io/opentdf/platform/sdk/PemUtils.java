package io.opentdf.platform.sdk;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * BouncyCastle-flavored PEM/X.509 helpers used only by tests. Kept here so the SDK
 * production classpath does not have a BouncyCastle dependency. The implementations
 * use BouncyCastle internally but expose standard JCA key interfaces, so callers can
 * pass results directly to JCA-based APIs.
 */
final class PemUtils {


    private PemUtils() {
    }

    static ECPublicKey publicKeyFromPem(String pemEncoding) {
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

    static ECPrivateKey privateKeyFromPem(String pemEncoding) {
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

    static String getPEMPublicKeyFromX509Cert(String pemInX509Format) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemInX509Format));
            X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) parser.readObject();
            parser.close();
            SubjectPublicKeyInfo publicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            ECPublicKey publicKey;
            try {
                publicKey = (ECPublicKey) converter.getPublicKey(publicKeyInfo);
            } catch (PEMException e) {
                throw new RuntimeException(e);
            }

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

    static byte[] compressECPublickey(String pemECPubKey) {
        try {
            KeyFactory ecKeyFac = KeyFactory.getInstance("EC");
            PemReader pemReader = new PemReader(new StringReader(pemECPubKey));
            PemObject pemObject = pemReader.readPemObject();
            PublicKey pubKey = ecKeyFac.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
            return ((org.bouncycastle.jce.interfaces.ECPublicKey) pubKey).getQ().getEncoded(true);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    static String publicKeyFromECPoint(byte[] ecPoint, String curveName) {
        try {
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
            ECPoint point = ecSpec.getCurve().decodePoint(ecPoint);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            StringWriter writer = new StringWriter();
            PemWriter pemWriter = new PemWriter(writer);
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
            return writer.toString();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
