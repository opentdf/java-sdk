package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.ECKeyPair;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Dispatcher and shared helpers for post-quantum key wrapping. Serves the
 * three hybrid algorithms (X-Wing, NIST EC + ML-KEM) AND pure ML-KEM-768 /
 * ML-KEM-1024 via the same {@link BouncyCastleKemProvider}.
 *
 * <p>Wire envelope is identical across both families — an ASN.1 DER SEQUENCE
 * with two IMPLICIT context-tagged OCTET STRINGs (built via
 * {@link #marshalEnvelope}):
 * <pre>SEQUENCE { [0] IMPLICIT OCTET STRING ciphertext, [1] IMPLICIT OCTET STRING encryptedDEK }</pre>
 *
 * <p>The DEK is AES-256-GCM sealed (12-byte IV prefix + 16-byte tag suffix).
 * What differs between the two families is the <b>AES-256 wrap key</b>:
 * <ul>
 *   <li><b>Hybrid:</b> HKDF-SHA256(combinedSecret, salt=SHA-256("TDF"),
 *       info=empty) — the KDF is load-bearing as the combiner for the two
 *       shared-secret halves.</li>
 *   <li><b>Pure ML-KEM:</b> the 32-byte FIPS 203 Decaps shared secret is used
 *       directly — no KDF. See
 *       {@link MLKEMAlgorithm#wrapDEK(byte[], byte[])} and platform ADR
 *       {@code 2026-06-16-mlkem-direct-key-wrap.md}.</li>
 * </ul>
 *
 * <p>The KAO {@code type} field disambiguates the two on the wire:
 * {@code "hybrid-wrapped"} for hybrid, {@code "mlkem-wrapped"} for pure ML-KEM.
 */
final class HybridCrypto {

    static final int WRAP_KEY_SIZE = 32;

    // ASN.1 tag bytes used by the envelope.
    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_CONTEXT_PRIMITIVE_0 = 0x80;
    private static final int TAG_CONTEXT_PRIMITIVE_1 = 0x81;

    private HybridCrypto() {}

    /**
     * Wrap a DEK against a PQC public-key PEM. Single dispatch site for all
     * algorithms ({@link BouncyCastleKemProvider} delegates here) so adding
     * a new algorithm is one switch case in each direction. Output bytes
     * are the raw envelope; caller base64-encodes for {@code keyAccess.wrappedKey}.
     */
    static byte[] wrapDEK(KeyType keyType, String publicKeyPEM, byte[] dek) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.wrapDEK(XWingKeyPair.pubKeyFromPem(publicKeyPEM), dek);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTAlgorithm.P256_MLKEM768.wrapDEK(
                        HybridNISTAlgorithm.P256_MLKEM768.pubKeyFromPem(publicKeyPEM), dek);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTAlgorithm.P384_MLKEM1024.wrapDEK(
                        HybridNISTAlgorithm.P384_MLKEM1024.pubKeyFromPem(publicKeyPEM), dek);
            case MLKEM768Key:
                return MLKEMAlgorithm.MLKEM_768.wrapDEK(
                        MLKEMAlgorithm.MLKEM_768.pubKeyFromPem(publicKeyPEM), dek);
            case MLKEM1024Key:
                return MLKEMAlgorithm.MLKEM_1024.wrapDEK(
                        MLKEMAlgorithm.MLKEM_1024.pubKeyFromPem(publicKeyPEM), dek);
            default:
                throw new SDKException("unsupported PQC key type: " + keyType);
        }
    }

    /**
     * Inverse of {@link #wrapDEK}; same dispatch table. Used by
     * {@link BouncyCastleKemProvider#unwrapDEK} and by unit tests.
     */
    static byte[] unwrapDEK(KeyType keyType, String privateKeyPEM, byte[] wrapped) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.unwrapDEK(XWingKeyPair.privateKeyFromPem(privateKeyPEM), wrapped);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTAlgorithm.P256_MLKEM768.unwrapDEK(
                        HybridNISTAlgorithm.P256_MLKEM768.privateKeyFromPem(privateKeyPEM), wrapped);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTAlgorithm.P384_MLKEM1024.unwrapDEK(
                        HybridNISTAlgorithm.P384_MLKEM1024.privateKeyFromPem(privateKeyPEM), wrapped);
            case MLKEM768Key:
                return MLKEMAlgorithm.MLKEM_768.unwrapDEK(
                        MLKEMAlgorithm.MLKEM_768.privateKeyFromPem(privateKeyPEM), wrapped);
            case MLKEM1024Key:
                return MLKEMAlgorithm.MLKEM_1024.unwrapDEK(
                        MLKEMAlgorithm.MLKEM_1024.privateKeyFromPem(privateKeyPEM), wrapped);
            default:
                throw new SDKException("unsupported PQC key type: " + keyType);
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
        int firstLenByte = c.readByte();
        // DER canonical encoding (X.690 §10.1): the minimum number of length bytes must be used,
        // and the first content byte must not be zero (otherwise a shorter form would have sufficed).
        if (firstLenByte == 0) {
            throw new SDKException("non-canonical ASN.1 length: leading zero byte in long-form");
        }
        int len = firstLenByte;
        for (int i = 1; i < numBytes; i++) {
            len = (len << 8) | c.readByte();
        }
        if (numBytes == 1 && len < 0x80) {
            throw new SDKException("non-canonical ASN.1 length: long-form used for value < 128 (got " + len + ")");
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

    /** Single concat helper for the {@code pqc.bc} package. */
    static byte[] concat(byte[] a, byte[] b) {
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
     *
     * <p>Duplicated rather than reusing {@code TDF.GLOBAL_KEY_SALT} because the
     * {@code TDF} class is package-private to {@code io.opentdf.platform.sdk}
     * and unreachable from this {@code pqc.bc} package. Computed once at class
     * load and returned as a defensive clone (HKDF input must not mutate).
     */
    static byte[] defaultTDFSalt() {
        return DEFAULT_TDF_SALT.clone();
    }

    private static final byte[] DEFAULT_TDF_SALT = computeDefaultTDFSalt();

    private static byte[] computeDefaultTDFSalt() {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            d.update("TDF".getBytes(StandardCharsets.UTF_8));
            return d.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("SHA-256 not available", e);
        }
    }

}
