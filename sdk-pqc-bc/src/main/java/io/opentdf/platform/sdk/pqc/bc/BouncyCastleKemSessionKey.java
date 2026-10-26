package io.opentdf.platform.sdk.pqc.bc;

import io.opentdf.platform.sdk.spi.KemProvider;

import java.util.Arrays;

/**
 * {@link KemProvider.KemSessionKey} returned by {@link BouncyCastleKemProvider}.
 * Owns the raw private key bytes (the same encoding the algorithm classes'
 * {@code unwrapDEK(byte[] rawPriv, ...)} take) and zeroes them on {@link #close()}.
 * The private key is never PEM-encoded or turned into a {@code String}.
 *
 * <p>BouncyCastle's key parameter objects, built inside each unwrap, keep
 * their own copies that cannot be wiped; they are unreachable once the
 * unwrap returns.
 */
final class BouncyCastleKemSessionKey implements KemProvider.KemSessionKey {

    /** One algorithm's raw-key unwrap, e.g. {@code MLKEMAlgorithm.MLKEM_768::unwrapDEK}. */
    @FunctionalInterface
    interface RawUnwrap {
        byte[] unwrapDEK(byte[] rawPrivateKey, byte[] wrapped);
    }

    private final String publicKeyPEM;
    private final byte[] privateKey;
    private final RawUnwrap unwrap;
    private boolean closed;

    /** Takes ownership of {@code privateKey}: the caller must not keep or reuse the array. */
    BouncyCastleKemSessionKey(String publicKeyPEM, byte[] privateKey, RawUnwrap unwrap) {
        this.publicKeyPEM = publicKeyPEM;
        this.privateKey = privateKey;
        this.unwrap = unwrap;
    }

    @Override
    public String publicKeyPEM() {
        return publicKeyPEM;
    }

    @Override
    public synchronized byte[] unwrapDEK(byte[] wrapped) {
        if (closed) {
            throw new IllegalStateException("KEM session key has been closed");
        }
        return unwrap.unwrapDEK(privateKey, wrapped);
    }

    @Override
    public synchronized void close() {
        Arrays.fill(privateKey, (byte) 0);
        closed = true;
    }
}
