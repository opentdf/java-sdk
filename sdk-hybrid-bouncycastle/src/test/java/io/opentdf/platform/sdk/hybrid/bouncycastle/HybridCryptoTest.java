package io.opentdf.platform.sdk.hybrid.bouncycastle;

import io.opentdf.platform.sdk.HybridKeyWrapProvider;
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
        int headerEnd = pem.indexOf('\n') + 1;
        String truncated = pem.substring(0, headerEnd) + pem.substring(headerEnd + 4);
        assertThrows(SDKException.class, () -> XWingKeyPair.pubKeyFromPem(truncated));
    }

    @Test
    void providerDispatcherSelectsCorrectScheme() {
        HybridKeyWrapProvider provider = new BouncyCastleHybridKeyWrapProvider();

        XWingKeyPair xw = XWingKeyPair.generate();
        byte[] xwWrapped = provider.wrapDEK(KeyType.HybridXWingKey, xw.publicKeyInPemFormat(), DEK);
        byte[] xwUnwrapped = provider.unwrapDEK(KeyType.HybridXWingKey, xw.privateKeyInPemFormat(), xwWrapped);
        assertArrayEquals(DEK, xwUnwrapped);

        HybridNISTKeyPair p256 = HybridNISTKeyPair.P256_MLKEM768.generate();
        byte[] p256Wrapped = provider.wrapDEK(KeyType.HybridSecp256r1MLKEM768Key,
                p256.publicKeyInPemFormat(), DEK);
        byte[] p256Unwrapped = provider.unwrapDEK(KeyType.HybridSecp256r1MLKEM768Key,
                p256.privateKeyInPemFormat(), p256Wrapped);
        assertArrayEquals(DEK, p256Unwrapped);

        HybridNISTKeyPair p384 = HybridNISTKeyPair.P384_MLKEM1024.generate();
        byte[] p384Wrapped = provider.wrapDEK(KeyType.HybridSecp384r1MLKEM1024Key,
                p384.publicKeyInPemFormat(), DEK);
        byte[] p384Unwrapped = provider.unwrapDEK(KeyType.HybridSecp384r1MLKEM1024Key,
                p384.privateKeyInPemFormat(), p384Wrapped);
        assertArrayEquals(DEK, p384Unwrapped);
    }

    @Test
    void providerRejectsNonHybridKeyType() {
        HybridKeyWrapProvider provider = new BouncyCastleHybridKeyWrapProvider();
        assertThrows(SDKException.class,
                () -> provider.wrapDEK(KeyType.RSA2048Key, "not-a-real-pem", DEK));
    }

    @Test
    void providerSupportsReturnsTrueForHybridTypesOnly() {
        HybridKeyWrapProvider provider = new BouncyCastleHybridKeyWrapProvider();
        assertTrue(provider.supports(KeyType.HybridXWingKey));
        assertTrue(provider.supports(KeyType.HybridSecp256r1MLKEM768Key));
        assertTrue(provider.supports(KeyType.HybridSecp384r1MLKEM1024Key));
        for (KeyType kt : KeyType.values()) {
            if (kt != KeyType.HybridXWingKey
                    && kt != KeyType.HybridSecp256r1MLKEM768Key
                    && kt != KeyType.HybridSecp384r1MLKEM1024Key) {
                assertEquals(false, provider.supports(kt), "supports() should be false for " + kt);
            }
        }
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
