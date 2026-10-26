package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import io.opentdf.platform.sdk.spi.KemProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link HybridCrypto#generateSessionKey}, the dispatcher backing
 * {@link BouncyCastleKemProvider#generateSessionKey} and (in the core {@code sdk}
 * module) {@code KASClient}'s KEM branch for the rewrap client "session key".
 *
 * <p>Each variant is exercised end-to-end the way KAS and KASClient use it:
 * generate a session key, wrap a DEK against its public PEM, unwrap through
 * the session key, assert equal. The negative cases check that the session
 * key and envelope fail closed: unwrapping must throw rather than return a DEK.
 */
class HybridCryptoSessionKeyTest {

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    /** Every hybrid and pure ML-KEM key type, so a newly added PQC type can't skip these tests. */
    static Stream<KeyType> pqcKeyTypes() {
        return Arrays.stream(KeyType.values()).filter(kt -> kt.isHybrid() || kt.isMLKEM());
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void generatedSessionKeyRoundTrips(KeyType keyType) {
        try (KemProvider.KemSessionKey sessionKey = HybridCrypto.generateSessionKey(keyType)) {
            assertTrue(sessionKey.publicKeyPEM().startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");

            byte[] wrapped = HybridCrypto.wrapDEK(keyType, sessionKey.publicKeyPEM(), DEK);
            assertArrayEquals(DEK, sessionKey.unwrapDEK(wrapped), "DEK round-trip via generated session key");
        }
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void otherSessionKeyOfSameTypeCannotUnwrap(KeyType keyType) {
        try (KemProvider.KemSessionKey recipient = HybridCrypto.generateSessionKey(keyType);
             KemProvider.KemSessionKey other = HybridCrypto.generateSessionKey(keyType)) {
            byte[] wrapped = HybridCrypto.wrapDEK(keyType, recipient.publicKeyPEM(), DEK);
            assertThrows(SDKException.class, () -> other.unwrapDEK(wrapped),
                    "a different session key of the same type must not unwrap the DEK");
        }
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void tamperedKemCiphertextCannotUnwrap(KeyType keyType) {
        try (KemProvider.KemSessionKey sessionKey = HybridCrypto.generateSessionKey(keyType)) {
            byte[][] parts = HybridCrypto.unmarshalEnvelope(
                    HybridCrypto.wrapDEK(keyType, sessionKey.publicKeyPEM(), DEK));

            // The midpoint of the KEM ciphertext is inside its ML-KEM part for every type
            // (the EC / X25519 share, where present, is appended after it). Decapsulation
            // implicitly rejects and yields a wrong wrap key, so AES-GCM must fail.
            parts[0][parts[0].length / 2] ^= 0x01;
            byte[] tampered = HybridCrypto.marshalEnvelope(parts[0], parts[1]);

            assertThrows(SDKException.class, () -> sessionKey.unwrapDEK(tampered),
                    "a flipped byte in the KEM ciphertext must not unwrap the DEK");
        }
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void tamperedEncryptedDekCannotUnwrap(KeyType keyType) {
        try (KemProvider.KemSessionKey sessionKey = HybridCrypto.generateSessionKey(keyType)) {
            byte[][] parts = HybridCrypto.unmarshalEnvelope(
                    HybridCrypto.wrapDEK(keyType, sessionKey.publicKeyPEM(), DEK));

            parts[1][parts[1].length / 2] ^= 0x01;
            byte[] tampered = HybridCrypto.marshalEnvelope(parts[0], parts[1]);

            assertThrows(SDKException.class, () -> sessionKey.unwrapDEK(tampered),
                    "a flipped byte in the AES-GCM sealed DEK must not unwrap");
        }
    }

    @ParameterizedTest
    @MethodSource("pqcKeyTypes")
    void closedSessionKeyCannotUnwrap(KeyType keyType) {
        KemProvider.KemSessionKey sessionKey = HybridCrypto.generateSessionKey(keyType);
        byte[] wrapped = HybridCrypto.wrapDEK(keyType, sessionKey.publicKeyPEM(), DEK);

        sessionKey.close();

        assertThrows(IllegalStateException.class, () -> sessionKey.unwrapDEK(wrapped),
                "a closed session key must not unwrap");
    }

    @Test
    void closeZeroesThePrivateKey() {
        byte[] privateKey = {1, 2, 3, 4};
        BouncyCastleKemSessionKey sessionKey =
                new BouncyCastleKemSessionKey("unused", privateKey, (priv, wrapped) -> priv.clone());
        assertArrayEquals(new byte[] {1, 2, 3, 4}, sessionKey.unwrapDEK(new byte[0]),
                "unwrap is handed the private key");

        sessionKey.close();

        assertArrayEquals(new byte[4], privateKey, "close must zero the private key");
    }
}
