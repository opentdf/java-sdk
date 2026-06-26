package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.spi.KemProvider;

import java.util.EnumSet;
import java.util.Set;

/**
 * BouncyCastle-backed {@link KemProvider}. Supports the post-quantum
 * {@link KeyType}s currently defined in the SDK:
 * <ul>
 *   <li><b>Hybrid:</b> {@link KeyType#HybridXWingKey},
 *       {@link KeyType#HybridSecp256r1MLKEM768Key},
 *       {@link KeyType#HybridSecp384r1MLKEM1024Key}</li>
 *   <li><b>Pure ML-KEM (FIPS 203):</b> {@link KeyType#MLKEM768Key},
 *       {@link KeyType#MLKEM1024Key}</li>
 * </ul>
 *
 * <p>Discovered by {@link io.opentdf.platform.sdk.spi.KemProviders} via
 * {@link java.util.ServiceLoader}; consumers don't construct this directly.
 * Lives in the optional {@code sdk-pqc-bc} module so the core {@code sdk}
 * jar has no compile-time dependency on BouncyCastle.
 */
public final class BouncyCastleKemProvider implements KemProvider {

    private static final Set<KeyType> SUPPORTED = EnumSet.of(
            KeyType.HybridXWingKey,
            KeyType.HybridSecp256r1MLKEM768Key,
            KeyType.HybridSecp384r1MLKEM1024Key,
            KeyType.MLKEM768Key,
            KeyType.MLKEM1024Key);

    /** Public no-arg constructor required by {@link java.util.ServiceLoader}. */
    public BouncyCastleKemProvider() {
        // Intentionally empty: ServiceLoader requires a public no-arg constructor;
        // all state is the SUPPORTED static set above and the stateless HybridCrypto helpers.
    }

    @Override
    public Set<KeyType> supportedKeyTypes() {
        return SUPPORTED;
    }

    @Override
    public byte[] wrapDEK(KeyType keyType, String publicKeyPEM, byte[] dek) {
        return HybridCrypto.wrapDEK(keyType, publicKeyPEM, dek);
    }

    @Override
    public byte[] unwrapDEK(KeyType keyType, String privateKeyPEM, byte[] wrapped) {
        return HybridCrypto.unwrapDEK(keyType, privateKeyPEM, wrapped);
    }
}
