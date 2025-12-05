package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.text.ParseException;
import java.util.Objects;

public class KeyAssertionValidator implements AssertionValidator {

    private final Config.AssertionVerificationKeys assertionVerificationKeys;

    private AssertionVerificationMode assertionVerificationMode = AssertionVerificationMode.FAIL_FAST;

    public KeyAssertionValidator(Config.AssertionVerificationKeys assertionVerificationKeys) {
        this.assertionVerificationKeys = assertionVerificationKeys;
    }

    @Override
    public String getSchema() {
        return "*";
    }

    @Override
    public void verify(Manifest.Assertion assertion, Manifest manifest) throws SDK.AssertionException {

        if (Objects.equals(assertion.binding.signature, "")) {
            throw new SDK.AssertionException("assertion has no cryptographic binding", assertion.id);
        }

        if (assertionVerificationKeys.isEmpty()) {
            if (Objects.requireNonNull(assertionVerificationMode) == AssertionVerificationMode.PERMISSIVE) {
                return;
            }
            throw new SDK.AssertionException("no verification keys configured for assertion validation", assertion.id);
        }
        AssertionConfig.AssertionKey assertionKey = assertionVerificationKeys.getKey(assertion.id);

        try {
            Manifest.Assertion.HashValues hashValues = assertion.verify(assertionKey);

            if(hashValues.getSchema() != null && !Objects.equals(hashValues.getSchema(), assertion.statement.schema)) {
                throw new SDK.AssertionException("Assertion schema mismatch", assertion.id);
            }

            if (!Objects.equals(assertion.hash(), hashValues.getAssertionHash())) {
                throw new SDK.AssertionException("Assertion hash mismatch", assertion.id);
            }

            Manifest.Assertion.verifyAssertionSignatureFormat(hashValues.getSignature(), assertion, manifest);
        } catch (ParseException | JOSEException | IOException e) {
            throw new SDK.AssertionException("failed to verify assertion signature", assertion.id);
        }
    }

    @Override
    public void validate(Manifest.Assertion assertion, TDFReader reader) throws SDK.AssertionException {
        if (assertionVerificationKeys.isEmpty()) {
            throw new SDK.AssertionException("no verification keys are trusted", assertion.id);
        }

        AssertionConfig.AssertionKey assertionKey = assertionVerificationKeys.getKey(assertion.id);

        if (assertionKey == null) {
            throw new SDK.AssertionException("no verification keys are trusted", assertion.id);
        }
    }

    public void setVerificationMode(@Nonnull AssertionVerificationMode assertionVerificationMode) {
        this.assertionVerificationMode = assertionVerificationMode;
    }
}
