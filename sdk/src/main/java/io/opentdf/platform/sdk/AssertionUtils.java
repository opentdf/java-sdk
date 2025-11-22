package io.opentdf.platform.sdk;

public class AssertionUtils {
    /**
     * Computes the data to be signed for an assertion.
     *
     * @param aggregateHash The hash of the TDF payload segments.
     * @param assertionHash The hash of the assertion itself.
     * @return The concatenated hash.
     */
    public static byte[] computeAssertionSignature(byte[] aggregateHash, byte[] assertionHash) {
        byte[] completeHash = new byte[aggregateHash.length + assertionHash.length];
        System.arraycopy(aggregateHash, 0, completeHash, 0, aggregateHash.length);
        System.arraycopy(assertionHash, 0, completeHash, aggregateHash.length, assertionHash.length);
        return completeHash;
    }
}
