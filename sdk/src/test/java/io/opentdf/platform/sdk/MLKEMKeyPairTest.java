package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for pure ML-KEM key wrapping. Every test runs once per parameter
 * set (ML-KEM-768 and ML-KEM-1024) so 1024 stays exercised even though no Go
 * KAS reference exists for it yet.
 *
 * Exercises the full producer/consumer path locally: generate keypair → PEM
 * round-trip → wrap a known DEK → unwrap with matching private key. If the
 * wire format drifts (e.g. someone re-orders ciphertext and encrypted-DEK,
 * or changes HKDF salt), the round-trip fails.
 */
class MLKEMKeyPairTest {

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes();
    private static final int AES_GCM_OVERHEAD = 12 + 16; // 12-byte nonce + 16-byte tag

    static Stream<MLKEMKeyPair> algorithms() {
        return Stream.of(MLKEMKeyPair.MLKEM_768, MLKEMKeyPair.MLKEM_1024);
    }

    @ParameterizedTest
    @MethodSource("algorithms")
    void roundTrip(MLKEMKeyPair alg) {
        MLKEMKeyPair kp = alg.generate();

        // PEM round-trip preserves both halves
        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        assertTrue(pubPem.startsWith("-----BEGIN " + headerFor(alg, "PUBLIC") + "-----"), "public PEM header");
        assertTrue(privPem.contains(headerFor(alg, "PRIVATE")), "private PEM header");

        byte[] rawPub = alg.pubKeyFromPem(pubPem);
        byte[] rawPriv = alg.privateKeyFromPem(privPem);
        assertEquals(alg.publicKeySize(), rawPub.length);
        assertEquals(MLKEMKeyPair.SEED_SIZE, rawPriv.length);

        // Wrap → expected blob length is ct + AES-GCM(12+|DEK|+16)
        byte[] wrapped = alg.wrapDEK(rawPub, DEK);
        assertNotNull(wrapped);
        assertEquals(alg.ciphertextSize() + DEK.length + AES_GCM_OVERHEAD, wrapped.length,
                "wrapped blob must be ct || nonce||ct||tag");

        // Unwrap recovers the original DEK
        byte[] unwrapped = alg.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped);
    }

    @ParameterizedTest
    @MethodSource("algorithms")
    void wrapRejectsWrongSizePublicKey(MLKEMKeyPair alg) {
        byte[] tooShort = new byte[alg.publicKeySize() - 1];
        SDKException ex = assertThrows(SDKException.class, () -> alg.wrapDEK(tooShort, DEK));
        assertTrue(ex.getMessage().contains("public key size"), ex.getMessage());
    }

    @ParameterizedTest
    @MethodSource("algorithms")
    void unwrapRejectsWrongSizePrivateKey(MLKEMKeyPair alg) {
        MLKEMKeyPair kp = alg.generate();
        byte[] wrapped = alg.wrapDEK(kp.getPublicKey(), DEK);
        byte[] badPriv = new byte[MLKEMKeyPair.SEED_SIZE - 1];
        SDKException ex = assertThrows(SDKException.class, () -> alg.unwrapDEK(badPriv, wrapped));
        assertTrue(ex.getMessage().contains("seed size"), ex.getMessage());
    }

    @ParameterizedTest
    @MethodSource("algorithms")
    void unwrapRejectsShortBlob(MLKEMKeyPair alg) {
        MLKEMKeyPair kp = alg.generate();
        byte[] tooShort = new byte[alg.ciphertextSize()]; // no room for the AES-GCM-wrapped DEK
        SDKException ex = assertThrows(SDKException.class, () -> alg.unwrapDEK(kp.getPrivateKey(), tooShort));
        assertTrue(ex.getMessage().contains("too short"), ex.getMessage());
    }

    @ParameterizedTest
    @MethodSource("algorithms")
    void tamperedCiphertextFailsAesGcmTag(MLKEMKeyPair alg) {
        MLKEMKeyPair kp = alg.generate();
        byte[] wrapped = alg.wrapDEK(kp.getPublicKey(), DEK);
        // Flip a bit inside the AES-GCM-wrapped DEK section — must fail the tag check
        wrapped[wrapped.length - 1] ^= 0x01;
        assertThrows(Exception.class, () -> alg.unwrapDEK(kp.getPrivateKey(), wrapped));
    }

    @Test
    void forKeyTypeDispatchesCorrectly() {
        assertEquals(MLKEMKeyPair.MLKEM_768, MLKEMKeyPair.forKeyType(KeyType.MLKEM768Key));
        assertEquals(MLKEMKeyPair.MLKEM_1024, MLKEMKeyPair.forKeyType(KeyType.MLKEM1024Key));
        assertThrows(SDKException.class, () -> MLKEMKeyPair.forKeyType(KeyType.RSA2048Key));
    }

    private static String headerFor(MLKEMKeyPair alg, String half) {
        return alg == MLKEMKeyPair.MLKEM_768
                ? "ML-KEM-768 " + half + " KEY"
                : "ML-KEM-1024 " + half + " KEY";
    }
}
