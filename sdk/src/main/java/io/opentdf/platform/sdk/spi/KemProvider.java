package io.opentdf.platform.sdk.spi;

import io.opentdf.platform.sdk.KeyType;

import java.util.Set;

/**
 * Service provider interface for post-quantum key encapsulation mechanisms.
 *
 * <p>Implementations live in optional sibling modules (e.g. {@code sdk-pqc-bc}
 * for the BouncyCastle-backed providers) and are discovered at runtime via
 * {@link java.util.ServiceLoader}. The core {@code sdk} module has no
 * compile-time dependency on any PQC library — this keeps the core jar
 * provider-agnostic per ADR 0001 and lets the {@code fips} Maven profile
 * exclude PQC entirely.
 *
 * <p>Wire-format contract: {@link #wrapDEK} returns the raw bytes that go
 * into {@code keyAccess.wrappedKey} (after base64 encoding by the caller).
 * The exact byte layout per {@link KeyType} is fixed by the platform spec
 * and must be byte-compatible with the Go SDK / KAS counterparts.
 */
public interface KemProvider {

    /**
     * @return the {@link KeyType}s this provider can wrap and unwrap.
     *         Used by {@link KemProviders} to build the dispatch table at
     *         registration time. The returned set must be non-null and should
     *         be unmodifiable and safe for concurrent iteration —
     *         {@link KemProviders} reads it once at registration and may
     *         retain a reference. {@link java.util.EnumSet#of} or
     *         {@link java.util.Collections#unmodifiableSet} are both fine.
     */
    Set<KeyType> supportedKeyTypes();

    /**
     * Wrap a data encryption key against a recipient's public-key PEM.
     *
     * @param keyType       hybrid or pure-PQC algorithm; must be a member of {@link #supportedKeyTypes()}
     * @param publicKeyPEM  recipient KAS public key, PEM-encoded
     * @param dek           the symmetric data encryption key being wrapped
     * @return              raw envelope bytes (caller base64-encodes for {@code keyAccess.wrappedKey})
     */
    byte[] wrapDEK(KeyType keyType, String publicKeyPEM, byte[] dek);

    /**
     * Inverse of {@link #wrapDEK}. Used by tests and any future client-side
     * decap path; the production decrypt flow defers unwrap to the KAS.
     */
    byte[] unwrapDEK(KeyType keyType, String privateKeyPEM, byte[] wrapped);
}
