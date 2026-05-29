package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.ECKeyPair;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Dispatcher and shared helpers for hybrid post-quantum key wrapping
 * (X-Wing and NIST EC + ML-KEM).
 *
 * Wire format: ASN.1 DER SEQUENCE with two IMPLICIT context-tagged OCTET STRINGs
 *   SEQUENCE { [0] IMPLICIT OCTET STRING ciphertext, [1] IMPLICIT OCTET STRING encryptedDEK }
 *
 * Derived AES-256 wrap key: HKDF-SHA256(combinedSecret, salt=SHA-256("TDF"), info=empty).
 * EncryptedDEK: AES-256-GCM(wrapKey).encrypt(DEK) with 12-byte IV prefix + 16-byte tag.
 */
final class HybridCrypto {

    static final int WRAP_KEY_SIZE = 32;

    // ASN.1 tag bytes used by the envelope.
    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_CONTEXT_PRIMITIVE_0 = 0x80;
    private static final int TAG_CONTEXT_PRIMITIVE_1 = 0x81;

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
        byte[] body = concat(
                encodeTLV(TAG_CONTEXT_PRIMITIVE_0, hybridCiphertext),
                encodeTLV(TAG_CONTEXT_PRIMITIVE_1, encryptedDEK));
        return encodeTLV(TAG_SEQUENCE, body);
    }

    /**
     * Parse the ASN.1 envelope. Returns {@code [hybridCiphertext, encryptedDEK]}.
     * Rejects trailing bytes (matches the Go {@code asn1.Unmarshal} strict behaviour).
     */
    static byte[][] unmarshalEnvelope(byte[] der) {
        Cursor c = new Cursor(der, 0);
        int tag = c.readByte();
        if (tag != TAG_SEQUENCE) {
            throw new SDKException("expected ASN.1 SEQUENCE (0x30), got 0x" + Integer.toHexString(tag));
        }
        int seqLen = readLength(c);
        int seqEnd = c.pos + seqLen;
        if (seqEnd > der.length) {
            throw new SDKException("hybrid wrapped key envelope length exceeds buffer");
        }
        if (seqEnd != der.length) {
            throw new SDKException("hybrid wrapped key envelope has trailing bytes");
        }
        byte[] hybridCt = readImplicitOctetString(c, 0);
        byte[] encDek = readImplicitOctetString(c, 1);
        if (c.pos != seqEnd) {
            throw new SDKException("hybrid wrapped key envelope SEQUENCE has trailing bytes");
        }
        return new byte[][] { hybridCt, encDek };
    }

    private static byte[] readImplicitOctetString(Cursor c, int expectedTagNo) {
        int expectedTag = TAG_CONTEXT_PRIMITIVE_0 | expectedTagNo;
        int tag = c.readByte();
        if (tag != expectedTag) {
            throw new SDKException("expected context tag " + expectedTagNo
                    + " (0x" + Integer.toHexString(expectedTag) + ") but got 0x" + Integer.toHexString(tag));
        }
        int len = readLength(c);
        if (c.pos + len > c.buf.length) {
            throw new SDKException("context-tagged element length exceeds buffer");
        }
        byte[] out = new byte[len];
        System.arraycopy(c.buf, c.pos, out, 0, len);
        c.pos += len;
        return out;
    }

    private static byte[] encodeTLV(int tag, byte[] content) {
        byte[] lenBytes = encodeLength(content.length);
        byte[] out = new byte[1 + lenBytes.length + content.length];
        out[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, out, 1, lenBytes.length);
        System.arraycopy(content, 0, out, 1 + lenBytes.length, content.length);
        return out;
    }

    private static byte[] encodeLength(int len) {
        if (len < 0) {
            throw new SDKException("negative ASN.1 length: " + len);
        }
        if (len < 0x80) {
            return new byte[] { (byte) len };
        }
        // Long form: 0x80 | numBytes, then big-endian length bytes.
        int numBytes = 0;
        int tmp = len;
        while (tmp > 0) { numBytes++; tmp >>>= 8; }
        byte[] out = new byte[1 + numBytes];
        out[0] = (byte) (0x80 | numBytes);
        for (int i = numBytes; i > 0; i--) {
            out[i] = (byte) (len & 0xFF);
            len >>>= 8;
        }
        return out;
    }

    private static int readLength(Cursor c) {
        int first = c.readByte();
        if ((first & 0x80) == 0) {
            return first;
        }
        int numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > 4) {
            // indefinite-length (numBytes == 0) is BER-only; DER rejects it.
            // > 4 would overflow a positive 32-bit int and is implausible for our envelope.
            throw new SDKException("invalid ASN.1 length encoding: numBytes=" + numBytes);
        }
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | c.readByte();
        }
        if (len < 0) {
            throw new SDKException("ASN.1 length overflowed signed int");
        }
        return len;
    }

    private static final class Cursor {
        final byte[] buf;
        int pos;
        Cursor(byte[] buf, int pos) { this.buf = buf; this.pos = pos; }
        int readByte() {
            if (pos >= buf.length) {
                throw new SDKException("unexpected end of ASN.1 input at offset " + pos);
            }
            return buf[pos++] & 0xFF;
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * HKDF-SHA256 → 32-byte AES wrap key. Delegates to
     * {@link ECKeyPair#calculateHKDF(byte[], byte[])} (HKDF-Extract + Expand,
     * empty info, L = 32 — the parameters all three hybrid algorithms use).
     */
    static byte[] deriveWrapKey(byte[] combinedSecret) {
        return ECKeyPair.calculateHKDF(defaultTDFSalt(), combinedSecret);
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
