package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import io.opentdf.platform.sdk.spi.KemProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link HybridCrypto#generateKeyPair}, the dispatcher backing
 * {@link BouncyCastleKemProvider#generateKeyPair} and (in the core {@code sdk}
 * module) {@code KASClient}'s KEM branch for the rewrap client "session key".
 *
 * <p>Each variant is exercised end-to-end through the same PEM-based
 * {@link KemProvider} contract KASClient uses: generate a fresh keypair, wrap
 * a DEK against its public PEM, unwrap against its private PEM, assert equal.
 * The negative cases check that the generated keypair and envelope fail
 * closed: unwrapping must throw rather than return a DEK.
 */
class HybridCryptoGenerateKeyPairTest {

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    /** Every hybrid and pure ML-KEM key type, so a newly added PQC type can't skip these tests. */
    static Stream<KeyType> pqcKeyTypes() {
        return Arrays.stream(KeyType.values()).filter(kt -> kt.isHybrid() || kt.isMLKEM());
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void generatedKeyPairRoundTrips(KeyType keyType) {
        KemProvider.KeyPairPem kp = HybridCrypto.generateKeyPair(keyType);

        assertTrue(kp.publicKeyPEM.startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");
        assertTrue(kp.privateKeyPEM.startsWith("-----BEGIN PRIVATE KEY-----"), "private PEM header");

        byte[] wrapped = HybridCrypto.wrapDEK(keyType, kp.publicKeyPEM, DEK);
        byte[] unwrapped = HybridCrypto.unwrapDEK(keyType, kp.privateKeyPEM, wrapped);
        assertArrayEquals(DEK, unwrapped, "DEK round-trip via generated keypair");
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void otherKeyPairOfSameTypeCannotUnwrap(KeyType keyType) {
        KemProvider.KeyPairPem recipient = HybridCrypto.generateKeyPair(keyType);
        KemProvider.KeyPairPem other = HybridCrypto.generateKeyPair(keyType);

        byte[] wrapped = HybridCrypto.wrapDEK(keyType, recipient.publicKeyPEM, DEK);
        assertThrows(SDKException.class,
                () -> HybridCrypto.unwrapDEK(keyType, other.privateKeyPEM, wrapped),
                "a different keypair of the same type must not unwrap the DEK");
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void tamperedKemCiphertextCannotUnwrap(KeyType keyType) {
        KemProvider.KeyPairPem kp = HybridCrypto.generateKeyPair(keyType);
        byte[][] parts = HybridCrypto.unmarshalEnvelope(HybridCrypto.wrapDEK(keyType, kp.publicKeyPEM, DEK));

        // The midpoint of the KEM ciphertext is inside its ML-KEM part for every type
        // (the EC / X25519 share, where present, is appended after it). Decapsulation
        // implicitly rejects and yields a wrong wrap key, so AES-GCM must fail.
        parts[0][parts[0].length / 2] ^= 0x01;
        byte[] tampered = HybridCrypto.marshalEnvelope(parts[0], parts[1]);

        assertThrows(SDKException.class,
                () -> HybridCrypto.unwrapDEK(keyType, kp.privateKeyPEM, tampered),
                "a flipped byte in the KEM ciphertext must not unwrap the DEK");
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void tamperedEncryptedDekCannotUnwrap(KeyType keyType) {
        KemProvider.KeyPairPem kp = HybridCrypto.generateKeyPair(keyType);
        byte[][] parts = HybridCrypto.unmarshalEnvelope(HybridCrypto.wrapDEK(keyType, kp.publicKeyPEM, DEK));

        parts[1][parts[1].length / 2] ^= 0x01;
        byte[] tampered = HybridCrypto.marshalEnvelope(parts[0], parts[1]);

        assertThrows(SDKException.class,
                () -> HybridCrypto.unwrapDEK(keyType, kp.privateKeyPEM, tampered),
                "a flipped byte in the AES-GCM sealed DEK must not unwrap");
    }
}
