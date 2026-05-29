package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import org.junit.jupiter.api.Test;

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

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes();

    @Test
    void xwingRoundTrip() {
        XWingKeyPair kp = XWingKeyPair.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        assertTrue(pubPem.startsWith("-----BEGIN XWING PUBLIC KEY-----"), "public PEM header");
        assertTrue(privPem.contains("XWING PRIVATE KEY"), "private PEM header");

        byte[] rawPub = XWingKeyPair.pubKeyFromPem(pubPem);
        byte[] rawPriv = XWingKeyPair.privateKeyFromPem(privPem);
        assertEquals(XWingKeyPair.PUBLIC_KEY_SIZE, rawPub.length);
        assertEquals(XWingKeyPair.PRIVATE_KEY_SIZE, rawPriv.length);

        byte[] wrapped = XWingKeyPair.wrapDEK(rawPub, DEK);
        assertNotNull(wrapped);
        // ASN.1 SEQUENCE header byte
        assertEquals((byte) 0x30, wrapped[0]);

        byte[] unwrapped = XWingKeyPair.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
    }

    @Test
    void p256mlkem768RoundTrip() {
        HybridNISTKeyPair kp = HybridNISTKeyPair.P256_MLKEM768.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        assertTrue(pubPem.contains("SECP256R1 MLKEM768 PUBLIC KEY"), "public PEM header");
        assertTrue(privPem.contains("SECP256R1 MLKEM768 PRIVATE KEY"), "private PEM header");

        byte[] rawPub = HybridNISTKeyPair.P256_MLKEM768.pubKeyFromPem(pubPem);
        byte[] rawPriv = HybridNISTKeyPair.P256_MLKEM768.privateKeyFromPem(privPem);
        assertEquals(65 + 1184, rawPub.length);
        assertEquals(32 + 64, rawPriv.length);

        byte[] wrapped = HybridNISTKeyPair.P256_MLKEM768.wrapDEK(rawPub, DEK);
        byte[] unwrapped = HybridNISTKeyPair.P256_MLKEM768.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
    }

    @Test
    void p384mlkem1024RoundTrip() {
        HybridNISTKeyPair kp = HybridNISTKeyPair.P384_MLKEM1024.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        assertTrue(pubPem.contains("SECP384R1 MLKEM1024 PUBLIC KEY"), "public PEM header");
        assertTrue(privPem.contains("SECP384R1 MLKEM1024 PRIVATE KEY"), "private PEM header");

        byte[] rawPub = HybridNISTKeyPair.P384_MLKEM1024.pubKeyFromPem(pubPem);
        byte[] rawPriv = HybridNISTKeyPair.P384_MLKEM1024.privateKeyFromPem(privPem);
        assertEquals(97 + 1568, rawPub.length);
        assertEquals(48 + 64, rawPriv.length);

        byte[] wrapped = HybridNISTKeyPair.P384_MLKEM1024.wrapDEK(rawPub, DEK);
        byte[] unwrapped = HybridNISTKeyPair.P384_MLKEM1024.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
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
        HybridNISTKeyPair p256 = HybridNISTKeyPair.P256_MLKEM768.generate();
        HybridNISTKeyPair p384 = HybridNISTKeyPair.P384_MLKEM1024.generate();

        byte[] p256Pub = HybridNISTKeyPair.P256_MLKEM768.pubKeyFromPem(p256.publicKeyInPemFormat());
        byte[] wrapped = HybridNISTKeyPair.P256_MLKEM768.wrapDEK(p256Pub, DEK);

        byte[] p384Priv = HybridNISTKeyPair.P384_MLKEM1024.privateKeyFromPem(p384.privateKeyInPemFormat());
        assertThrows(SDKException.class,
                () -> HybridNISTKeyPair.P384_MLKEM1024.unwrapDEK(p384Priv, wrapped),
                "P-384 private key must reject a P-256 wrapped envelope");
    }

    @Test
    void pemBlockTypeMismatchRejected() {
        XWingKeyPair kp = XWingKeyPair.generate();
        String pem = kp.publicKeyInPemFormat();
        String mangled = pem.replace("XWING PUBLIC KEY", "WRONG PUBLIC KEY");
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

        HybridNISTKeyPair p256 = HybridNISTKeyPair.P256_MLKEM768.generate();
        byte[] p256Wrapped = HybridCrypto.wrapDEK(KeyType.HybridSecp256r1MLKEM768Key,
                p256.publicKeyInPemFormat(), DEK);
        byte[] p256Priv = HybridNISTKeyPair.P256_MLKEM768.privateKeyFromPem(p256.privateKeyInPemFormat());
        assertArrayEquals(DEK, HybridNISTKeyPair.P256_MLKEM768.unwrapDEK(p256Priv, p256Wrapped));

        HybridNISTKeyPair p384 = HybridNISTKeyPair.P384_MLKEM1024.generate();
        byte[] p384Wrapped = HybridCrypto.wrapDEK(KeyType.HybridSecp384r1MLKEM1024Key,
                p384.publicKeyInPemFormat(), DEK);
        byte[] p384Priv = HybridNISTKeyPair.P384_MLKEM1024.privateKeyFromPem(p384.privateKeyInPemFormat());
        assertArrayEquals(DEK, HybridNISTKeyPair.P384_MLKEM1024.unwrapDEK(p384Priv, p384Wrapped));
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
}
