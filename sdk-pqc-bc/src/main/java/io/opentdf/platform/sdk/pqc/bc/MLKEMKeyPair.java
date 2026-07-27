package io.opentdf.platform.sdk.pqc.bc;

/**
 * Holds a pure ML-KEM (FIPS 203) keypair as raw bytes plus the {@link MLKEMAlgorithm}
 * variant they belong to. Created exclusively by {@link MLKEMAlgorithm#generate()};
 * the constructor stays package-private so external callers go through the
 * algorithm dispatcher.
 *
 * <p>{@code publicKey} is the raw FIPS 203 encapsulation key
 * ({@link MLKEMAlgorithm#publicKeySize()} bytes). {@code privateKey} is the
 * 64-byte seed {@code (d || z)} per FIPS 203 §6 — not the expanded private
 * key. BC's {@code MLKEMPrivateKeyParameters} reconstructs the full key from
 * the seed at decapsulation time.
 */
public final class MLKEMKeyPair {

    private final MLKEMAlgorithm algorithm;
    private final byte[] publicKey;
    private final byte[] privateKey;

    MLKEMKeyPair(MLKEMAlgorithm algorithm, byte[] publicKey, byte[] privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public MLKEMAlgorithm algorithm() { return algorithm; }
    public byte[] getPublicKey() { return publicKey.clone(); }
    public byte[] getPrivateKey() { return privateKey.clone(); }

    /** SPKI {@code -----BEGIN PUBLIC KEY-----} block with the algorithm's OID. */
    public String publicKeyInPemFormat() {
        return HybridSpki.encodeSpkiPem(algorithm.oid(), publicKey);
    }

    /** PKCS#8 {@code -----BEGIN PRIVATE KEY-----} block carrying the 64-byte seed. */
    public String privateKeyInPemFormat() {
        return HybridSpki.encodePkcs8Pem(algorithm.oid(), privateKey);
    }
}
