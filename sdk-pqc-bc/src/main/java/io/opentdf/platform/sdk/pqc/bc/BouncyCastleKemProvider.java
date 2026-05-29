package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;
import io.opentdf.platform.sdk.spi.KemProvider;

import java.util.EnumSet;
import java.util.Set;

/**
 * BouncyCastle-backed {@link KemProvider}. Supports the three hybrid PQC
 * {@link KeyType}s currently defined in the SDK:
 * <ul>
 *   <li>{@link KeyType#HybridXWingKey} (X-Wing)</li>
 *   <li>{@link KeyType#HybridSecp256r1MLKEM768Key}</li>
 *   <li>{@link KeyType#HybridSecp384r1MLKEM1024Key}</li>
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
            KeyType.HybridSecp384r1MLKEM1024Key);

    /** Public no-arg constructor required by {@link java.util.ServiceLoader}. */
    public BouncyCastleKemProvider() {}

    @Override
    public Set<KeyType> supportedKeyTypes() {
        return SUPPORTED;
    }

    @Override
    public byte[] wrapDEK(KeyType keyType, String publicKeyPEM, byte[] dek) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.wrapDEK(XWingKeyPair.pubKeyFromPem(publicKeyPEM), dek);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTKeyPair.P256_MLKEM768.wrapDEK(
                        HybridNISTKeyPair.P256_MLKEM768.pubKeyFromPem(publicKeyPEM), dek);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTKeyPair.P384_MLKEM1024.wrapDEK(
                        HybridNISTKeyPair.P384_MLKEM1024.pubKeyFromPem(publicKeyPEM), dek);
            default:
                throw new SDKException("BouncyCastleKemProvider does not handle: " + keyType);
        }
    }

    @Override
    public byte[] unwrapDEK(KeyType keyType, String privateKeyPEM, byte[] wrapped) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.unwrapDEK(XWingKeyPair.privateKeyFromPem(privateKeyPEM), wrapped);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTKeyPair.P256_MLKEM768.unwrapDEK(
                        HybridNISTKeyPair.P256_MLKEM768.privateKeyFromPem(privateKeyPEM), wrapped);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTKeyPair.P384_MLKEM1024.unwrapDEK(
                        HybridNISTKeyPair.P384_MLKEM1024.privateKeyFromPem(privateKeyPEM), wrapped);
            default:
                throw new SDKException("BouncyCastleKemProvider does not handle: " + keyType);
        }
    }
}
