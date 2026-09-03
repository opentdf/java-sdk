package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.spi.KemProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link HybridCrypto#generateKeyPair}, the dispatcher backing
 * {@link BouncyCastleKemProvider#generateKeyPair} and (in the core {@code sdk}
 * module) {@code KASClient}'s KEM branch for the rewrap client "session key".
 *
 * <p>Each variant is exercised end-to-end through the same PEM-based
 * {@link KemProvider} contract KASClient uses: generate a fresh keypair, wrap
 * a DEK against its public PEM, unwrap against its private PEM, assert equal.
 */
class HybridCryptoGenerateKeyPairTest {

    private static final byte[] DEK = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @EnumSource(value = KeyType.class, names = {
            "HybridXWingKey",
            "HybridSecp256r1MLKEM768Key",
            "HybridSecp384r1MLKEM1024Key",
            "MLKEM768Key",
            "MLKEM1024Key"})
    void generatedKeyPairRoundTrips(KeyType keyType) {
        KemProvider.KeyPairPem kp = HybridCrypto.generateKeyPair(keyType);

        assertTrue(kp.publicKeyPEM.startsWith("-----BEGIN PUBLIC KEY-----"), "public PEM header");
        assertTrue(kp.privateKeyPEM.startsWith("-----BEGIN PRIVATE KEY-----"), "private PEM header");

        byte[] wrapped = HybridCrypto.wrapDEK(keyType, kp.publicKeyPEM, DEK);
        byte[] unwrapped = HybridCrypto.unwrapDEK(keyType, kp.privateKeyPEM, wrapped);
        assertArrayEquals(DEK, unwrapped, "DEK round-trip via generated keypair");
    }
}
