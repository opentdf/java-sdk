package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.Manifest.Assertion;

public interface AssertionBinder {
    /**
     * Creates and signs an assertion, binding it to the manifest.
     *
     * @param manifest The manifest of the TDF.
     * @param aggregateHash The aggregate hash of the TDF payload.
     * @return The signed assertion.
     * @throws SDK.AssertionException If an error occurs during binding.
     */
    Assertion bind(Manifest manifest, byte[] aggregateHash) throws SDK.AssertionException;
}
