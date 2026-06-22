package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for hybrid post-quantum key wrapping. Mirrors
 * {@code lib/ocrypto/xwing_test.go} and {@code lib/ocrypto/hybrid_nist_test.go}.
 *
 * Each scheme is exercised through a full round-trip: generate keypair → PEM
 * round-trip → wrap DEK → unwrap DEK → assert equal. The unwrap path is
 * also used as a wire-format guard: if marshal/unmarshal drift, the round-trip
 * fails.
 */
class HybridCryptoTest {

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    void xwingRoundTrip() {
        XWingKeyPair kp = XWingKeyPair.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        // Standard SPKI/PKCS#8 envelope (draft-connolly-cfrg-xwing-kem-10); the X-Wing
        // OID 1.3.6.1.4.1.62253.25722 sits inside the AlgorithmIdentifier.
        assertTrue(pubPem.startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");
        assertTrue(privPem.startsWith("-----BEGIN PRIVATE KEY-----"), "private PEM header");

        byte[] rawPub = XWingKeyPair.pubKeyFromPem(pubPem);
        byte[] rawPriv = XWingKeyPair.privateKeyFromPem(privPem);
        assertEquals(XWingKeyPair.PUBLIC_KEY_SIZE, rawPub.length);
        assertEquals(XWingKeyPair.PRIVATE_KEY_SEED_SIZE, rawPriv.length);

        byte[] wrapped = XWingKeyPair.wrapDEK(rawPub, DEK);
        assertNotNull(wrapped);
        // ASN.1 SEQUENCE header byte
        assertEquals((byte) 0x30, wrapped[0]);

        byte[] unwrapped = XWingKeyPair.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
    }

    @Test
    void p256mlkem768RoundTrip() {
        HybridNISTKeyPair kp = HybridNISTAlgorithm.P256_MLKEM768.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        // draft-ietf-lamps-pq-composite-kem-14: standard PUBLIC/PRIVATE KEY blocks,
        // OID 1.3.6.1.5.5.7.6.59 inside AlgorithmIdentifier.
        assertTrue(pubPem.startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");
        assertTrue(privPem.startsWith("-----BEGIN PRIVATE KEY-----"), "private PEM header");

        byte[] rawPub = HybridNISTAlgorithm.P256_MLKEM768.pubKeyFromPem(pubPem);
        byte[] rawPriv = HybridNISTAlgorithm.P256_MLKEM768.privateKeyFromPem(privPem);
        assertEquals(1184 + 65, rawPub.length);
        // Private key = mlkemSeed(64) || ECPrivateKey(RFC 5915 DER, variable length)
        assertTrue(rawPriv.length > 64, "private key must contain mlkemSeed + ECPrivateKey DER");

        byte[] wrapped = HybridNISTAlgorithm.P256_MLKEM768.wrapDEK(rawPub, DEK);
        byte[] unwrapped = HybridNISTAlgorithm.P256_MLKEM768.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
    }

    @Test
    void p384mlkem1024RoundTrip() {
        HybridNISTKeyPair kp = HybridNISTAlgorithm.P384_MLKEM1024.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        assertTrue(pubPem.startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");
        assertTrue(privPem.startsWith("-----BEGIN PRIVATE KEY-----"), "private PEM header");

        byte[] rawPub = HybridNISTAlgorithm.P384_MLKEM1024.pubKeyFromPem(pubPem);
        byte[] rawPriv = HybridNISTAlgorithm.P384_MLKEM1024.privateKeyFromPem(privPem);
        assertEquals(1568 + 97, rawPub.length);
        assertTrue(rawPriv.length > 64, "private key must contain mlkemSeed + ECPrivateKey DER");

        byte[] wrapped = HybridNISTAlgorithm.P384_MLKEM1024.wrapDEK(rawPub, DEK);
        byte[] unwrapped = HybridNISTAlgorithm.P384_MLKEM1024.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
    }

    @Test
    void crossSchemeOidRejected() {
        // An X-Wing SPKI PEM passed to a NIST hybrid decoder must fail on the
        // AlgorithmIdentifier OID mismatch, not on size.
        XWingKeyPair xw = XWingKeyPair.generate();
        String xwPubPem = xw.publicKeyInPemFormat();
        assertThrows(SDKException.class,
                () -> HybridNISTAlgorithm.P256_MLKEM768.pubKeyFromPem(xwPubPem));
    }

    @Test
    void wrapProducesDifferentCiphertextEachCall() {
        XWingKeyPair kp = XWingKeyPair.generate();
        byte[] rawPub = XWingKeyPair.pubKeyFromPem(kp.publicKeyInPemFormat());
        byte[] w1 = XWingKeyPair.wrapDEK(rawPub, DEK);
        byte[] w2 = XWingKeyPair.wrapDEK(rawPub, DEK);
        assertNotEquals(Arrays.toString(w1), Arrays.toString(w2),
                "wrap must be randomised (fresh ephemeral + GCM IV) — two calls produced identical ciphertext");
    }

    @Test
    void crossSchemePrivateKeyFails() {
        HybridNISTKeyPair p256 = HybridNISTAlgorithm.P256_MLKEM768.generate();
        HybridNISTKeyPair p384 = HybridNISTAlgorithm.P384_MLKEM1024.generate();

        byte[] p256Pub = HybridNISTAlgorithm.P256_MLKEM768.pubKeyFromPem(p256.publicKeyInPemFormat());
        byte[] wrapped = HybridNISTAlgorithm.P256_MLKEM768.wrapDEK(p256Pub, DEK);

        byte[] p384Priv = HybridNISTAlgorithm.P384_MLKEM1024.privateKeyFromPem(p384.privateKeyInPemFormat());
        assertThrows(SDKException.class,
                () -> HybridNISTAlgorithm.P384_MLKEM1024.unwrapDEK(p384Priv, wrapped),
                "P-384 private key must reject a P-256 wrapped envelope");
    }

    @Test
    void pemBlockTypeMismatchRejected() {
        XWingKeyPair kp = XWingKeyPair.generate();
        String pem = kp.publicKeyInPemFormat();
        // Swap the standard SPKI block-type header for a bogus one — strict parser must reject.
        String mangled = pem.replace("PUBLIC KEY", "WRONG PUBLIC KEY");
        assertThrows(SDKException.class, () -> XWingKeyPair.pubKeyFromPem(mangled));
    }

    @Test
    void pemBodySizeMismatchRejected() {
        XWingKeyPair kp = XWingKeyPair.generate();
        String pem = kp.publicKeyInPemFormat();
        // Truncate one base64 char inside the body — yields wrong byte length after decode.
        int headerEnd = pem.indexOf('\n') + 1;
        String truncated = pem.substring(0, headerEnd) + pem.substring(headerEnd + 4);
        assertThrows(SDKException.class, () -> XWingKeyPair.pubKeyFromPem(truncated));
    }

    @Test
    void dispatcherSelectsCorrectScheme() {
        // Round-trip via the public HybridCrypto.wrapDEK dispatcher for each key type.
        XWingKeyPair xw = XWingKeyPair.generate();
        byte[] xwWrapped = HybridCrypto.wrapDEK(KeyType.HybridXWingKey, xw.publicKeyInPemFormat(), DEK);
        byte[] xwPriv = XWingKeyPair.privateKeyFromPem(xw.privateKeyInPemFormat());
        assertArrayEquals(DEK, XWingKeyPair.unwrapDEK(xwPriv, xwWrapped));

        HybridNISTKeyPair p256 = HybridNISTAlgorithm.P256_MLKEM768.generate();
        byte[] p256Wrapped = HybridCrypto.wrapDEK(KeyType.HybridSecp256r1MLKEM768Key,
                p256.publicKeyInPemFormat(), DEK);
        byte[] p256Priv = HybridNISTAlgorithm.P256_MLKEM768.privateKeyFromPem(p256.privateKeyInPemFormat());
        assertArrayEquals(DEK, HybridNISTAlgorithm.P256_MLKEM768.unwrapDEK(p256Priv, p256Wrapped));

        HybridNISTKeyPair p384 = HybridNISTAlgorithm.P384_MLKEM1024.generate();
        byte[] p384Wrapped = HybridCrypto.wrapDEK(KeyType.HybridSecp384r1MLKEM1024Key,
                p384.publicKeyInPemFormat(), DEK);
        byte[] p384Priv = HybridNISTAlgorithm.P384_MLKEM1024.privateKeyFromPem(p384.privateKeyInPemFormat());
        assertArrayEquals(DEK, HybridNISTAlgorithm.P384_MLKEM1024.unwrapDEK(p384Priv, p384Wrapped));
    }

    @Test
    void dispatcherRejectsNonHybridKeyType() {
        assertThrows(SDKException.class,
                () -> HybridCrypto.wrapDEK(KeyType.RSA2048Key, "not-a-real-pem", DEK));
    }

    @Test
    void truncatedEnvelopeRejected() {
        XWingKeyPair kp = XWingKeyPair.generate();
        byte[] rawPub = XWingKeyPair.pubKeyFromPem(kp.publicKeyInPemFormat());
        byte[] rawPriv = XWingKeyPair.privateKeyFromPem(kp.privateKeyInPemFormat());
        byte[] wrapped = XWingKeyPair.wrapDEK(rawPub, DEK);
        byte[] truncated = Arrays.copyOf(wrapped, wrapped.length - 10);
        assertThrows(SDKException.class, () -> XWingKeyPair.unwrapDEK(rawPriv, truncated));
    }

    @Test
    void nonCanonicalDerLengthRejected() {
        // Hand-craft a SEQUENCE whose length uses BER long-form for a value that fits
        // in short-form (5 < 128) — strict DER per X.690 §10.1 must reject this.
        // Bytes: 0x30 (SEQUENCE) 0x81 (long-form, 1 length byte) 0x05 (length=5) + 5 dummy content bytes
        byte[] badEnvelope = new byte[] {
                (byte) 0x30, (byte) 0x81, (byte) 0x05,
                0x01, 0x02, 0x03, 0x04, 0x05
        };
        assertThrows(SDKException.class,
                () -> HybridCrypto.unmarshalEnvelope(badEnvelope),
                "long-form length encoding for value < 128 must be rejected as non-canonical DER");
    }

    @Test
    void derLengthWithLeadingZeroRejected() {
        // 0x30 (SEQUENCE) 0x82 (long-form, 2 length bytes) 0x00 0x80 (= 128, but the leading
        // zero is redundant — shorter form 0x81 0x80 would do). Strict DER rejects.
        byte[] badEnvelope = new byte[] {
                (byte) 0x30, (byte) 0x82, (byte) 0x00, (byte) 0x80
        };
        assertThrows(SDKException.class,
                () -> HybridCrypto.unmarshalEnvelope(badEnvelope),
                "leading-zero byte in long-form length must be rejected as non-canonical DER");
    }
}
