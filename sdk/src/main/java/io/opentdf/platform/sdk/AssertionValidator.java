package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.Manifest.Assertion;

public interface AssertionValidator {
    /**
     * Returns the schema URI that this validator can handle.
     *
     * @return The schema URI.
     */
    String getSchema();

    /**
     * Performs a cryptographic check of the assertion.
     *
     * @param assertion The assertion to verify.
     * @param reader    The TDF reader.
     * @param aggregateHash The aggregate hash of the TDF payload.
     * @throws SDK.AssertionException If the verification fails.
     */
    void verify(Assertion assertion, TDFReader reader, byte[] aggregateHash) throws SDK.AssertionException;

    /**
     * Performs a policy check of the assertion.
     *
     * @param assertion The assertion to validate.
     * @param reader    The TDF reader.
     * @throws SDK.AssertionException If the validation fails.
     */
    void validate(Assertion assertion, TDFReader reader) throws SDK.AssertionException;
}
