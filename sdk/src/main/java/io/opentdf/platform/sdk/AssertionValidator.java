package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import io.opentdf.platform.sdk.Manifest.Assertion;

import java.io.IOException;
import java.text.ParseException;

public interface AssertionValidator {
  /**
   * // Schema returns the schema URI this validator handles.
   * 	// The schema identifies the assertion format and version.
   * 	// Examples: "urn:opentdf:system:metadata:v1", "urn:opentdf:key:assertion:v1"
   *
   * @return The schema URI.
   */
  String getSchema();

    void setVerificationMode(AssertionVerificationMode verificationMode);

  /**
   * // Verify checks the assertion's cryptographic binding.
   * 	//
   * 	// Example:
   * 	//   assertionHash, _ := a.GetHash()
   * 	//   manifest := r.Manifest()
   * 	//   expectedSig, _ := manifest.ComputeAssertionSignature(assertionHash)
   *
   * @param assertion The assertion to verify.
   * @param manifest  The manifest.
   * @throws SDK.AssertionException If the verification fails.
   */
  void verify(Assertion assertion, Manifest manifest) throws SDK.AssertionException;

    /**
     * // Validate checks the assertion's policy and trust requirements
     *
     * @param assertion The assertion to validate.
     * @param reader    The TDF reader.
     * @throws SDK.AssertionException If the validation fails.
     */
    void validate(Assertion assertion, TDFReader reader) throws SDK.AssertionException;
}
