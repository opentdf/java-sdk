package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.Manifest.Assertion;

public interface AssertionBinder {
  /**
   * Bind creates and signs an assertion, binding it to the given manifest.
   * 	// The implementation is responsible for both configuring the assertion and binding it.
   *
   * @param manifest The manifest.
   * @return The assertion.
   * @throws SDK.AssertionException If an error occurs during binding.
   */
  Assertion bind(Manifest manifest) throws SDK.AssertionException;
}
