package io.opentdf.platform.sdk;

/**
 * Service Provider Interface for HKDF (RFC 5869) key derivation.
 * Implementations are discovered at runtime via {@link java.util.ServiceLoader}.
 * When no implementation is on the classpath, {@link ECKeyPair#calculateHKDF} falls
 * back to the JDK-native HmacSHA256 implementation.
 *
 * The FIPS-approved implementation is {@code io.opentdf.platform:sdk-fips-bc},
 * which uses the BouncyCastle FIPS KDF API directly.
 */
public interface HkdfProvider {
    /**
     * Derive a 32-byte key using HKDF-Extract+Expand with SHA-256 HMAC PRF
     * and empty info, per RFC 5869.
     */
    byte[] computeHKDF(byte[] salt, byte[] secret);
}
