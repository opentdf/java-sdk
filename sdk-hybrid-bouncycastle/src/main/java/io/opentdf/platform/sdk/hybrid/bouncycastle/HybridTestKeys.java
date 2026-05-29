package io.opentdf.platform.sdk.hybrid.bouncycastle;

import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDKException;

/**
 * Test-support helper for generating hybrid post-quantum keypairs as PEM-encoded
 * pairs. Provided as a public utility on the published jar so the {@code sdk}
 * module's tests (and downstream consumers writing their own round-trip tests)
 * can exercise the SPI without importing BouncyCastle directly.
 */
public final class HybridTestKeys {

    /** Holder for a PEM-encoded hybrid keypair. */
    public static final class PemPair {
        public final String publicKeyPem;
        public final String privateKeyPem;

        PemPair(String publicKeyPem, String privateKeyPem) {
            this.publicKeyPem = publicKeyPem;
            this.privateKeyPem = privateKeyPem;
        }
    }

    private HybridTestKeys() {}

    /**
     * Generate a fresh hybrid keypair for the given type and return both halves
     * as PEM blocks suitable for use with {@link io.opentdf.platform.sdk.HybridKeyWrapProvider}.
     */
    public static PemPair generate(KeyType keyType) {
        switch (keyType) {
            case HybridXWingKey: {
                XWingKeyPair kp = XWingKeyPair.generate();
                return new PemPair(kp.publicKeyInPemFormat(), kp.privateKeyInPemFormat());
            }
            case HybridSecp256r1MLKEM768Key: {
                HybridNISTKeyPair kp = HybridNISTKeyPair.P256_MLKEM768.generate();
                return new PemPair(kp.publicKeyInPemFormat(), kp.privateKeyInPemFormat());
            }
            case HybridSecp384r1MLKEM1024Key: {
                HybridNISTKeyPair kp = HybridNISTKeyPair.P384_MLKEM1024.generate();
                return new PemPair(kp.publicKeyInPemFormat(), kp.privateKeyInPemFormat());
            }
            default:
                throw new SDKException("not a hybrid key type: " + keyType);
        }
    }
}
