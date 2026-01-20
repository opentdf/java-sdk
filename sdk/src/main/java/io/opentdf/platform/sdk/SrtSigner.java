package io.opentdf.platform.sdk;

public interface SrtSigner {
    byte[] sign(byte[] input) throws Exception;

    String alg();
}
