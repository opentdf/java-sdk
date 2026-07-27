package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.SDKException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for pure ML-KEM-768 / ML-KEM-1024 key wrapping. Mirrors the
 * shape of {@code HybridCryptoTest} but for FIPS 203 standalone (no EC
 * combiner) — generate keypair → SPKI/PKCS#8 PEM round-trip → wrap DEK →
 * unwrap DEK → assert byte-equal. The unwrap path also acts as a wire-format
 * guard: if the ASN.1 envelope marshal/unmarshal drifts, the round-trip
 * fails.
 */
class MLKEMKeyPairTest {

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    private static Stream<Arguments> variants() {
        return Stream.of(
                Arguments.of(MLKEMAlgorithm.MLKEM_768),
                Arguments.of(MLKEMAlgorithm.MLKEM_1024));
    }

    @ParameterizedTest
    @MethodSource("variants")
    void roundTrip(MLKEMAlgorithm algo) {
        MLKEMKeyPair kp = algo.generate();

        String pubPem = kp.publicKeyInPemFormat();
        String privPem = kp.privateKeyInPemFormat();
        // Standard SPKI/PKCS#8 envelope; the FIPS 203 OID
        // (2.16.840.1.101.3.4.4.2 / .3) sits inside the AlgorithmIdentifier.
        assertTrue(pubPem.startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");
        assertTrue(privPem.startsWith("-----BEGIN PRIVATE KEY-----"), "private PEM header");

        byte[] rawPub = algo.pubKeyFromPem(pubPem);
        byte[] rawPriv = algo.privateKeyFromPem(privPem);
        assertEquals(algo.publicKeySize(), rawPub.length);
        assertEquals(MLKEMAlgorithm.SEED_SIZE, rawPriv.length);
        assertArrayEquals(kp.getPublicKey(), rawPub, "public key round-trip");
        assertArrayEquals(kp.getPrivateKey(), rawPriv, "private key round-trip");

        byte[] wrapped = algo.wrapDEK(rawPub, DEK);
        assertNotNull(wrapped);
        // ASN.1 SEQUENCE — first byte is the SEQUENCE tag, same as the hybrid envelope.
        assertEquals((byte) 0x30, wrapped[0], "ASN.1 SEQUENCE tag");

        byte[] unwrapped = algo.unwrapDEK(rawPriv, wrapped);
        assertArrayEquals(DEK, unwrapped, "DEK round-trip");
    }

    @ParameterizedTest
    @MethodSource("variants")
    void rejectsWrongOIDInPem(MLKEMAlgorithm algo) {
        // 768 keypair, decoded with the 1024 OID expectation (or vice versa) — should fail.
        MLKEMAlgorithm other = (algo == MLKEMAlgorithm.MLKEM_768)
                ? MLKEMAlgorithm.MLKEM_1024 : MLKEMAlgorithm.MLKEM_768;
        String pem = other.generate().publicKeyInPemFormat();
        SDKException ex = assertThrows(SDKException.class, () -> algo.pubKeyFromPem(pem));
        // Message comes from HybridSpki.decodeSpkiPem; just confirm it mentions OID/algorithm mismatch.
        assertTrue(ex.getMessage().toLowerCase().contains("oid")
                || ex.getMessage().toLowerCase().contains("mismatch"),
                "expected OID-mismatch message, got: " + ex.getMessage());
    }

    @ParameterizedTest
    @MethodSource("variants")
    void rejectsWrongSizedPublicKey(MLKEMAlgorithm algo) {
        byte[] tooShort = new byte[algo.publicKeySize() - 1];
        SDKException ex = assertThrows(SDKException.class, () -> algo.wrapDEK(tooShort, DEK));
        assertTrue(ex.getMessage().contains("public key size"), ex.getMessage());
    }

    @ParameterizedTest
    @MethodSource("variants")
    void rejectsMalformedEnvelope(MLKEMAlgorithm algo) {
        MLKEMKeyPair kp = algo.generate();
        // A two-byte blob can't possibly be a valid SEQUENCE-of-two-OCTET-STRINGs envelope.
        // HybridCrypto.unmarshalEnvelope should reject before we even reach AES-GCM.
        byte[] malformed = new byte[] { (byte) 0x30, 0x00 };
        assertThrows(SDKException.class,
                () -> algo.unwrapDEK(kp.getPrivateKey(), malformed));
    }

    @ParameterizedTest
    @MethodSource("variants")
    void rejectsTamperedCiphertext(MLKEMAlgorithm algo) {
        MLKEMKeyPair kp = algo.generate();
        byte[] wrapped = algo.wrapDEK(kp.getPublicKey(), DEK);
        // Flip a bit in the AES-GCM tag (last byte of the envelope) — the envelope
        // still parses as valid ASN.1, but AES-GCM auth fails on unwrap. Avoids
        // touching the ASN.1 headers (wrapped[0..~6]) which would surface as a
        // parse error instead of the more interesting auth-failure path.
        wrapped[wrapped.length - 1] ^= 0x01;
        assertThrows(Exception.class,
                () -> algo.unwrapDEK(kp.getPrivateKey(), wrapped),
                "tampered AES-GCM tag must not unwrap");
    }
}
