package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.text.ParseException;
import java.util.Objects;

public class DEKAssertionValidator implements AssertionValidator {

    private AssertionVerificationMode verificationMode = AssertionVerificationMode.FAIL_FAST;

    private AssertionConfig.AssertionKey dekKey;

    public DEKAssertionValidator(AssertionConfig.AssertionKey dekKey) {
        this.dekKey = dekKey;
    }

    @Override
    public String getSchema() {
        return "";
    }

    @Override
    public void setVerificationMode(@Nonnull AssertionVerificationMode verificationMode) {
        this.verificationMode = verificationMode;
    }

    @Override
    public void verify(Manifest.Assertion assertion, Manifest manifest) throws SDK.AssertionException {
        try {
            Manifest.Assertion.HashValues hashValues = assertion.verify(dekKey);
            var hashOfAssertionAsHex = assertion.hash();
            if (!Objects.equals(hashOfAssertionAsHex, hashValues.getAssertionHash())) {
                throw new SDK.AssertionException("assertion hash mismatch", assertion.id);
            }
        } catch (JOSEException e) {
            throw new SDKException("error validating assertion hash", e);
        } catch (ParseException e) {
            throw new SDK.AssertionException("error parsing assertion hash", assertion.id);
        } catch (IOException e) {
            throw new SDK.AssertionException("error reading assertion hash", assertion.id);
        }
    }

    // Validate does nothing - DEK-based validation doesn't check trust/policy.
    @Override
    public void validate(Manifest.Assertion assertion, TDFReader reader) throws SDK.AssertionException {}
}
