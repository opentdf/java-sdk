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

    /**
     * Generate a fresh ephemeral rewrap "session key" for {@code keyType} — the
     * key a client generates and sends with a rewrap request so KAS can wrap
     * the response DEK back to it — as opposed to a KAS-managed wrapping key
     * (see {@link #wrapDEK}).
     *
     * <p>The default implementation throws {@link UnsupportedOperationException},
     * so providers written before this method existed keep compiling and
     * loading. They still serve {@link #wrapDEK} / {@link #unwrapDEK}; only a
     * rewrap that asks for a session key of their type fails. Providers that
     * can generate session keys should override it.
     *
     * @param keyType hybrid or pure-PQC algorithm; must be a member of {@link #supportedKeyTypes()}
     * @return         the generated session key; the caller must {@link KemSessionKey#close() close} it
     * @throws UnsupportedOperationException if this provider cannot generate session keys
     */
    default KemSessionKey generateSessionKey(KeyType keyType) {
        throw new UnsupportedOperationException(
                getClass().getName() + " does not support generating " + keyType + " session keys");
    }

    /**
     * An ephemeral rewrap session key. Only the public half is exposed; the
     * private half stays inside the provider, which uses it to unwrap the
     * rewrap response and erases it on {@link #close()}.
     *
     * <p>Erasure covers the key material the provider holds. Copies made
     * inside a crypto library while unwrapping may not be erasable; they
     * become unreachable once {@link #unwrapDEK} returns.
     */
    interface KemSessionKey extends AutoCloseable {
        /** @return the public key to send to KAS, as an SPKI PEM */
        String publicKeyPEM();

        /**
         * Unwrap a DEK that KAS wrapped to {@link #publicKeyPEM()}.
         *
         * @throws IllegalStateException if this key has been closed
         */
        byte[] unwrapDEK(byte[] wrapped);

        /** Erase the private key. Further {@link #unwrapDEK} calls fail. */
        @Override
        void close();
    }
}
