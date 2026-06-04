package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.KeyType;

/**
 * A keypair produced by {@link HybridNISTAlgorithm#generate}. Holds the raw
 * public and private key bytes alongside a reference back to the algorithm
 * that produced them (for size validation and PEM headers).
 *
 * <p>This type carries key material only — algorithm-level operations
 * ({@code wrapDEK}, {@code unwrapDEK}, {@code pubKeyFromPem}, etc.) live on
 * {@link HybridNISTAlgorithm}. The split keeps the static algorithm templates
 * from being type-indistinguishable from the keypairs they produce.
 */
public final class HybridNISTKeyPair {

    private final HybridNISTAlgorithm algorithm;
    private final byte[] publicKey;
    private final byte[] privateKey;

    HybridNISTKeyPair(HybridNISTAlgorithm algorithm, byte[] publicKey, byte[] privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public HybridNISTAlgorithm algorithm() { return algorithm; }
    public KeyType keyType() { return algorithm.keyType(); }

    public byte[] getPublicKey() { return publicKey.clone(); }
    public byte[] getPrivateKey() { return privateKey.clone(); }

    public String publicKeyInPemFormat() {
        return HybridSpki.encodeSpkiPem(algorithm.oid(), publicKey);
    }

    public String privateKeyInPemFormat() {
        return HybridSpki.encodePkcs8Pem(algorithm.oid(), privateKey);
    }
}
