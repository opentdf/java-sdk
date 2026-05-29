package io.opentdf.platform.sdk.hybrid.bouncycastle;

import io.opentdf.platform.sdk.HybridKeyWrapProvider;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;

/**
 * BouncyCastle-backed {@link HybridKeyWrapProvider} covering X-Wing,
 * P-256 + ML-KEM-768, and P-384 + ML-KEM-1024. Discovered at runtime via
 * {@code META-INF/services/io.opentdf.platform.sdk.HybridKeyWrapProvider}.
 */
public final class BouncyCastleHybridKeyWrapProvider implements HybridKeyWrapProvider {

    @Override
    public boolean supports(KeyType keyType) {
        if (keyType == null) {
            return false;
        }
        switch (keyType) {
            case HybridXWingKey:
            case HybridSecp256r1MLKEM768Key:
            case HybridSecp384r1MLKEM1024Key:
                return true;
            default:
                return false;
        }
    }

    @Override
    public byte[] wrapDEK(KeyType keyType, String publicKeyPem, byte[] dek) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.wrapDEK(XWingKeyPair.pubKeyFromPem(publicKeyPem), dek);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTKeyPair.P256_MLKEM768.wrapDEK(
                        HybridNISTKeyPair.P256_MLKEM768.pubKeyFromPem(publicKeyPem), dek);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTKeyPair.P384_MLKEM1024.wrapDEK(
                        HybridNISTKeyPair.P384_MLKEM1024.pubKeyFromPem(publicKeyPem), dek);
            default:
                throw new SDKException("unsupported hybrid key type: " + keyType);
        }
    }

    @Override
    public byte[] unwrapDEK(KeyType keyType, String privateKeyPem, byte[] wrappedDek) {
        switch (keyType) {
            case HybridXWingKey:
                return XWingKeyPair.unwrapDEK(XWingKeyPair.privateKeyFromPem(privateKeyPem), wrappedDek);
            case HybridSecp256r1MLKEM768Key:
                return HybridNISTKeyPair.P256_MLKEM768.unwrapDEK(
                        HybridNISTKeyPair.P256_MLKEM768.privateKeyFromPem(privateKeyPem), wrappedDek);
            case HybridSecp384r1MLKEM1024Key:
                return HybridNISTKeyPair.P384_MLKEM1024.unwrapDEK(
                        HybridNISTKeyPair.P384_MLKEM1024.privateKeyFromPem(privateKeyPem), wrappedDek);
            default:
                throw new SDKException("unsupported hybrid key type: " + keyType);
        }
    }
}
