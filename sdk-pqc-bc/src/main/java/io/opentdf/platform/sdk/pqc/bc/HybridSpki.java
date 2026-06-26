package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.SDKException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Base64;

/**
 * SPKI ({@code SubjectPublicKeyInfo}, X.509) and PKCS#8
 * ({@code OneAsymmetricKey}) encode/parse helpers for KEM public/private
 * keys, plus RFC 5915 {@code ECPrivateKey} encode/parse for the EC half of
 * NIST hybrid private keys. Despite the {@code Hybrid} in the class name,
 * the encode/decode logic is algorithm-agnostic — it serves pure ML-KEM
 * (FIPS 203) the same as the hybrid schemes.
 *
 * <p>The PEM format for all supported algorithms is the standard
 * {@code -----BEGIN PUBLIC KEY-----} / {@code -----BEGIN PRIVATE KEY-----}
 * envelope; the {@link AlgorithmIdentifier} OID inside dispatches to the
 * correct scheme.
 *
 * <p>Hybrid OIDs (params absent for all three):
 * <ul>
 *   <li>{@code 1.3.6.1.5.5.7.6.59} — P-256 + ML-KEM-768</li>
 *   <li>{@code 1.3.6.1.5.5.7.6.63} — P-384 + ML-KEM-1024</li>
 *   <li>{@code 1.3.6.1.4.1.62253.25722} — X-Wing</li>
 * </ul>
 *
 * <p>Pure ML-KEM OIDs (NIST FIPS 203, params absent):
 * <ul>
 *   <li>{@code 2.16.840.1.101.3.4.4.2} — ML-KEM-768</li>
 *   <li>{@code 2.16.840.1.101.3.4.4.3} — ML-KEM-1024</li>
 * </ul>
 *
 * <p>Uses BouncyCastle's ASN.1 helpers — already on the classpath via
 * {@code sdk-pqc-bc}. No new BC compile-time surface area for the core sdk.
 */
final class HybridSpki {

    static final ASN1ObjectIdentifier OID_P256_MLKEM768 = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.59");
    static final ASN1ObjectIdentifier OID_P384_MLKEM1024 = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.63");
    static final ASN1ObjectIdentifier OID_XWING = new ASN1ObjectIdentifier("1.3.6.1.4.1.62253.25722");
    static final ASN1ObjectIdentifier OID_MLKEM768 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.2");
    static final ASN1ObjectIdentifier OID_MLKEM1024 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.3");

    private static final String PEM_TYPE_PUBLIC = "PUBLIC KEY";
    private static final String PEM_TYPE_PRIVATE = "PRIVATE KEY";

    private HybridSpki() {}

    /**
     * Encode {@code rawPublicKey} as an SPKI PEM block with the given algorithm
     * OID. The raw bytes go into the SPKI {@code subjectPublicKey} BIT STRING
     * verbatim (no further wrapping).
     */
    static String encodeSpkiPem(ASN1ObjectIdentifier algorithmOid, byte[] rawPublicKey) {
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(algorithmOid);
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, rawPublicKey);
            return pemEncode(PEM_TYPE_PUBLIC, spki.getEncoded("DER"));
        } catch (IOException e) {
            throw new SDKException("failed to encode SPKI for OID " + algorithmOid, e);
        }
    }

    /**
     * Encode {@code rawPrivateKey} as a PKCS#8 PEM block with the given algorithm
     * OID. The raw bytes go into the PKCS#8 {@code privateKey} OCTET STRING
     * verbatim (no further wrapping), matching the Go side's
     * {@code OneAsymmetricKey.PrivateKey []byte} layout.
     *
     * <p>Hand-built via {@link DERSequence} because BC's
     * {@code PrivateKeyInfo(AlgorithmIdentifier, ASN1Encodable)} constructor
     * DER-encodes the encodable first, which would add an inner OCTET STRING
     * wrapper around our raw bytes.
     */
    static String encodePkcs8Pem(ASN1ObjectIdentifier algorithmOid, byte[] rawPrivateKey) {
        try {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(algorithmOid);
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(0));                          // version v1 = 0
            v.add(algId);                                       // privateKeyAlgorithm
            v.add(new DEROctetString(rawPrivateKey));           // privateKey OCTET STRING (raw bytes)
            byte[] der = new DERSequence(v).getEncoded("DER");
            return pemEncode(PEM_TYPE_PRIVATE, der);
        } catch (IOException e) {
            throw new SDKException("failed to encode PKCS#8 for OID " + algorithmOid, e);
        }
    }

    /**
     * Decode an SPKI PEM block, validate the algorithm OID matches {@code expectedOid},
     * and return the raw {@code subjectPublicKey} bytes.
     */
    static byte[] decodeSpkiPem(String pem, ASN1ObjectIdentifier expectedOid) {
        byte[] der = stripPemAndDecode(pem, PEM_TYPE_PUBLIC);
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
            ASN1ObjectIdentifier actualOid = spki.getAlgorithm().getAlgorithm();
            if (!expectedOid.equals(actualOid)) {
                throw new SDKException("SPKI OID mismatch: expected " + expectedOid + ", got " + actualOid);
            }
            return spki.getPublicKeyData().getBytes();
        } catch (IOException e) {
            throw new SDKException("failed to parse SPKI", e);
        }
    }

    /**
     * Decode a PKCS#8 PEM block, validate the algorithm OID matches {@code expectedOid},
     * and return the raw {@code privateKey} bytes.
     */
    static byte[] decodePkcs8Pem(String pem, ASN1ObjectIdentifier expectedOid) {
        byte[] der = stripPemAndDecode(pem, PEM_TYPE_PRIVATE);
        try {
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
            ASN1ObjectIdentifier actualOid = pki.getPrivateKeyAlgorithm().getAlgorithm();
            if (!expectedOid.equals(actualOid)) {
                throw new SDKException("PKCS#8 OID mismatch: expected " + expectedOid + ", got " + actualOid);
            }
            return pki.getPrivateKey().getOctets();
        } catch (IOException e) {
            throw new SDKException("failed to parse PKCS#8", e);
        }
    }

    /**
     * Encode an EC private-key scalar as RFC 5915 {@code ECPrivateKey} DER —
     * {@code SEQUENCE { version=1, privateKey OCTET STRING, ... }}. Used as the
     * EC half of a NIST hybrid private key per draft-14.
     */
    static byte[] encodeEcPrivateKey(BigInteger scalar, int orderBitLength) {
        try {
            return new ECPrivateKey(orderBitLength, scalar).getEncoded("DER");
        } catch (IOException e) {
            throw new SDKException("failed to encode RFC 5915 ECPrivateKey", e);
        }
    }

    /**
     * Parse RFC 5915 {@code ECPrivateKey} DER and return the scalar as an unsigned
     * {@link BigInteger}.
     */
    static BigInteger decodeEcPrivateKey(byte[] der) {
        try {
            ECPrivateKey ec = ECPrivateKey.getInstance(ASN1Primitive.fromByteArray(der));
            return ec.getKey();
        } catch (IOException e) {
            throw new SDKException("failed to parse RFC 5915 ECPrivateKey", e);
        }
    }

    private static String pemEncode(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    private static byte[] stripPemAndDecode(String pem, String expectedType) {
        String header = "-----BEGIN " + expectedType + "-----";
        String footer = "-----END " + expectedType + "-----";
        int headerIdx = pem.indexOf(header);
        int footerIdx = pem.indexOf(footer);
        if (headerIdx < 0 || footerIdx < 0 || footerIdx <= headerIdx) {
            throw new SDKException("failed to parse PEM block of type " + expectedType);
        }
        String body = pem.substring(headerIdx + header.length(), footerIdx).replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new SDKException("failed to base64-decode PEM body for " + expectedType, e);
        }
    }
}
