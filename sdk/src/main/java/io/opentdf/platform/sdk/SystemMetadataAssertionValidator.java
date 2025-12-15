package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.text.ParseException;
import java.util.Objects;

public class SystemMetadataAssertionValidator implements AssertionValidator {

    private final byte[] payloadKey;

    private AssertionVerificationMode verificationMode = AssertionVerificationMode.FAIL_FAST;

    public SystemMetadataAssertionValidator(byte[] payloadKey) {
        this.payloadKey = payloadKey;
    }

    @Override
    public String getSchema() {
        return SystemMetadataAssertionBinder.SYSTEM_METADATA_SCHEMA_V1;
    }

    @Override
    public void setVerificationMode(@Nonnull AssertionVerificationMode verificationMode) {
        this.verificationMode = verificationMode;
    }

    @Override
    public void verify(Manifest.Assertion assertion, Manifest manifest) throws SDK.AssertionException {
        boolean isValidSchema = Objects.equals(assertion.statement.schema, SystemMetadataAssertionBinder.SYSTEM_METADATA_SCHEMA_V1) ||
                Objects.equals(assertion.statement.schema, "");

        if (!isValidSchema) {
            throw new SDK.AssertionException("System Metadata assertion schema is invalid", assertion.id);
        }

        AssertionConfig.AssertionKey assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                payloadKey);

        try {
            Manifest.Assertion.HashValues hashValues = assertion.verify(assertionKey);
            var hashOfAssertionAsHex = assertion.hash();
            if (!Objects.equals(hashOfAssertionAsHex, hashValues.getAssertionHash())) {
                throw new SDK.AssertionException("assertion hash mismatch", assertion.id);
            }
        } catch (JOSEException e) {
            throw new SDK.AssertionException("error validating assertion hash", assertion.id);
        } catch (ParseException e) {
            throw new SDK.AssertionException("error parsing assertion hash", assertion.id);
        } catch (IOException e) {
            throw new SDK.AssertionException("error reading assertion hash", assertion.id);
        }
    }

    // Validate does nothing.
    @Override
    public void validate(Manifest.Assertion assertion, TDFReader reader) throws SDK.AssertionException {}

}
