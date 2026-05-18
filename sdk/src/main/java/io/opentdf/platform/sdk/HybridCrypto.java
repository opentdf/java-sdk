package io.opentdf.platform.sdk;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Dispatcher and shared helpers for hybrid post-quantum key wrapping
 * (X-Wing and NIST EC + ML-KEM). Mirrors the lib/ocrypto Go package.
 *
 * Wire format: ASN.1 DER SEQUENCE with two IMPLICIT context-tagged OCTET STRINGs
 *   SEQUENCE { [0] IMPLICIT OCTET STRING ciphertext, [1] IMPLICIT OCTET STRING encryptedDEK }
 *
 * Derived AES-256 wrap key: HKDF-SHA256(combinedSecret, salt=SHA-256("TDF"), info=empty).
 * EncryptedDEK: AES-256-GCM(wrapKey).encrypt(DEK) with 12-byte IV prefix + 16-byte tag.
 */
final class HybridCrypto {

    static final int WRAP_KEY_SIZE = 32;

    private HybridCrypto() {}

    /**
     * Wrap a DEK against a hybrid public-key PEM. Dispatches across X-Wing and NIST hybrid types.
     * Returns the ASN.1-encoded envelope used in {@code wrappedKey} for {@code hybrid-wrapped} key access.
     */
    static byte[] wrapDEK(KeyType keyType, String publicKeyPEM, byte[] dek) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.wrapDEK(XWingKeyPair.pubKeyFromPem(publicKeyPEM), dek);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTKeyPair.P256_MLKEM768.wrapDEK(
                        HybridNISTKeyPair.P256_MLKEM768.pubKeyFromPem(publicKeyPEM), dek);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTKeyPair.P384_MLKEM1024.wrapDEK(
                        HybridNISTKeyPair.P384_MLKEM1024.pubKeyFromPem(publicKeyPEM), dek);
            default:
                throw new SDKException("unsupported hybrid key type: " + keyType);
        }
    }

    /**
     * Build the ASN.1 envelope from a hybrid KEM ciphertext and the AES-GCM(iv||ct) encrypted DEK.
     */
    static byte[] marshalEnvelope(byte[] hybridCiphertext, byte[] encryptedDEK) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 0, new DEROctetString(hybridCiphertext)));
        v.add(new DERTaggedObject(false, 1, new DEROctetString(encryptedDEK)));
        try {
            return new DERSequence(v).getEncoded("DER");
        } catch (IOException e) {
            throw new SDKException("failed to encode hybrid wrapped key envelope", e);
        }
    }

    /**
     * Parse the ASN.1 envelope. Returns {@code [hybridCiphertext, encryptedDEK]}.
     * Rejects trailing bytes (matches the Go {@code asn1.Unmarshal} strict behaviour).
     */
    static byte[][] unmarshalEnvelope(byte[] der) {
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
            ASN1Primitive prim = in.readObject();
            if (prim == null) {
                throw new SDKException("hybrid wrapped key envelope is empty");
            }
            if (in.readObject() != null) {
                throw new SDKException("hybrid wrapped key envelope has trailing bytes");
            }
            ASN1Sequence seq = ASN1Sequence.getInstance(prim);
            if (seq.size() != 2) {
                throw new SDKException("hybrid wrapped key envelope must have 2 elements, got " + seq.size());
            }
            byte[] hybridCt = readImplicitOctetString(seq.getObjectAt(0), 0);
            byte[] encDek = readImplicitOctetString(seq.getObjectAt(1), 1);
            return new byte[][] { hybridCt, encDek };
        } catch (IOException e) {
            throw new SDKException("failed to decode hybrid wrapped key envelope", e);
        }
    }

    private static byte[] readImplicitOctetString(org.bouncycastle.asn1.ASN1Encodable enc, int expectedTag) {
        ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(enc);
        if (tagged.getTagNo() != expectedTag) {
            throw new SDKException("expected context tag " + expectedTag + " but got " + tagged.getTagNo());
        }
        return org.bouncycastle.asn1.ASN1OctetString.getInstance(tagged, false).getOctets();
    }

    /**
     * HKDF-SHA256 → 32-byte AES wrap key. {@code salt=null} substitutes the default TDF salt.
     */
    static byte[] deriveWrapKey(byte[] combinedSecret, byte[] salt, byte[] info) {
        byte[] effSalt = (salt == null || salt.length == 0) ? defaultTDFSalt() : salt;
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(combinedSecret, effSalt, info));
        byte[] out = new byte[WRAP_KEY_SIZE];
        hkdf.generateBytes(out, 0, out.length);
        return out;
    }

    /**
     * SHA-256("TDF") — matches the Go {@code defaultTDFSalt()} and Java {@code TDF.GLOBAL_KEY_SALT}.
     */
    static byte[] defaultTDFSalt() {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            d.update("TDF".getBytes());
            return d.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("SHA-256 not available", e);
        }
    }

    /**
     * Encode a raw key into a PEM block with the given header type.
     */
    static String rawToPem(String blockType, byte[] raw, int expectedSize) {
        if (raw.length != expectedSize) {
            throw new SDKException("invalid " + blockType + " size: got " + raw.length + " want " + expectedSize);
        }
        String b64 = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(raw);
        return "-----BEGIN " + blockType + "-----\n" + b64 + "\n-----END " + blockType + "-----\n";
    }

    /**
     * Decode a PEM block of the expected type and content size. Strict on header type and size.
     */
    static byte[] decodeSizedPemBlock(String pem, String expectedType, int expectedSize) {
        String header = "-----BEGIN " + expectedType + "-----";
        String footer = "-----END " + expectedType + "-----";
        int headerIdx = pem.indexOf(header);
        int footerIdx = pem.indexOf(footer);
        if (headerIdx < 0 || footerIdx < 0 || footerIdx <= headerIdx) {
            throw new SDKException("failed to parse PEM formatted " + expectedType);
        }
        String body = pem.substring(headerIdx + header.length(), footerIdx).replaceAll("\\s", "");
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new SDKException("failed to base64-decode " + expectedType + " PEM body", e);
        }
        if (raw.length != expectedSize) {
            throw new SDKException("invalid " + expectedType + " size: got " + raw.length + " want " + expectedSize);
        }
        return raw;
    }
}
