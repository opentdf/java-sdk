package io.opentdf.platform.sdk;

import static io.opentdf.platform.sdk.TDF.TDF_SPEC_VERSION;

public class SystemMetadataAssertionBinder implements AssertionBinder {
    public static final String SYSTEM_METADATA_SCHEMA_V1 = "system-metadata-v1";

    @Override
    public Manifest.Assertion bind(Manifest manifest) {
        AssertionConfig assertionConfig = AssertionConfig.getSystemMetadataAssertionConfig(TDF_SPEC_VERSION);

        assertionConfig.statement.schema = SYSTEM_METADATA_SCHEMA_V1;

        Manifest.Assertion assertion = new Manifest.Assertion();
        assertion.id = assertionConfig.id;
        assertion.type = assertionConfig.type.toString();
        assertion.scope = assertionConfig.scope.toString();
        assertion.statement = assertionConfig.statement;
        assertion.appliesToState = assertionConfig.appliesToState.toString();

        return assertion;
    }

}
