package io.opentdf.platform.sdk;

import com.nimbusds.jose.KeyLengthException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ConfigBasedAssertionBinder implements AssertionBinder {
    private final AssertionConfig assertionConfig;

    public ConfigBasedAssertionBinder(AssertionConfig assertionConfig) {
        this.assertionConfig = assertionConfig;
    }

    @Override
    public Manifest.Assertion bind(Manifest manifest) throws SDK.AssertionException {
        Manifest.Assertion assertion = new Manifest.Assertion();
        assertion.id = assertionConfig.id;
        assertion.type = assertionConfig.type.toString();
        assertion.scope = assertionConfig.scope.toString();
        assertion.statement = assertionConfig.statement;
        assertion.appliesToState = assertionConfig.appliesToState.toString();

        try {
            ByteArrayOutputStream aggregateHash = Manifest.computeAggregateHash(manifest.encryptionInformation.integrityInformation.segments, manifest.payload.isEncrypted);
            boolean hexEncodeRootAndSegmentHashes = manifest.tdfVersion == null || manifest.tdfVersion.isEmpty();
            Manifest.Assertion.HashValues hashValues = Manifest.Assertion.calculateAssertionHashValues(aggregateHash, assertion, hexEncodeRootAndSegmentHashes);
            if (assertionConfig.signingKey != null && assertionConfig.signingKey.isDefined()) {
                assertion.sign(hashValues, assertionConfig.signingKey);
            }
            // otherwise no explicit signing key provided - use the payload key (DEK)
            // this is handled by passing the payload key from the TDF creation context
            // for now, return the unsigned assertion - it will be signed by a DEK-based binder
        } catch (IOException e) {
            throw new SDK.AssertionException("error reading assertion hash", assertionConfig.id);
        } catch (KeyLengthException e) {
            throw new SDK.AssertionException("error signing assertion", assertionConfig.id);
        }
        return assertion;
    }

}
