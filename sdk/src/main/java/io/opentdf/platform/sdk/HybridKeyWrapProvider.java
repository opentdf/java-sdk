package io.opentdf.platform.sdk;

/**
 * Service Provider Interface for hybrid post-quantum key wrapping (X-Wing and
 * NIST EC + ML-KEM). Implementations are discovered at runtime via
 * {@link java.util.ServiceLoader} so the {@code sdk} jar itself carries no
 * compile-time dependency on the underlying crypto library.
 *
 * The reference implementation is {@code io.opentdf.platform:sdk-hybrid-bouncycastle},
 * which provides X-Wing and {@code P-256/384 + ML-KEM} via BouncyCastle.
 */
public interface HybridKeyWrapProvider {

    /** Whether this provider can wrap/unwrap for the given hybrid key type. */
    boolean supports(KeyType keyType);

    /**
     * Wrap a 32-byte DEK against a hybrid public-key PEM, returning the
     * ASN.1 envelope used as {@code wrappedKey} for {@code hybrid-wrapped} key access.
     */
    byte[] wrapDEK(KeyType keyType, String publicKeyPem, byte[] dek);

    /**
     * Unwrap a DEK from an ASN.1 envelope using a hybrid private-key PEM.
     */
    byte[] unwrapDEK(KeyType keyType, String privateKeyPem, byte[] wrappedDek);
}
