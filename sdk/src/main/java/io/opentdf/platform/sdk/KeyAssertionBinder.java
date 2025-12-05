package io.opentdf.platform.sdk;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;


public class KeyAssertionBinder implements AssertionBinder {

    public static final String KEY_ASSERTION_ID = "assertion-key";
    public static final String KEY_ASSERTION_SCHEMA = "urn:opentdf:key:assertion:v1";

    private final AssertionConfig.AssertionKey privateKey;
    private final AssertionConfig.AssertionKey publicKey;
    private final String statementValue;

    public KeyAssertionBinder(AssertionConfig.AssertionKey privateKey, AssertionConfig.AssertionKey publicKey, String statementValue) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.statementValue = statementValue;
    }

    @Override
    public Manifest.Assertion bind(Manifest manifest) throws SDK.AssertionException {
        Manifest.Assertion assertion = new Manifest.Assertion();
        assertion.id = KEY_ASSERTION_ID;
        assertion.type = "other";
        assertion.scope = "payload";
        assertion.statement = new AssertionConfig.Statement();
        assertion.statement.format = "json";
        assertion.statement.schema = KEY_ASSERTION_SCHEMA;
        assertion.statement.value = statementValue;
        assertion.appliesToState = "unencrypted";

        RSAKey publicKeyJwk = new RSAKey.Builder((RSAPublicKey) publicKey.key)
                .algorithm(Algorithm.parse(publicKey.alg.toString()))
                .build();

        var protectedHeaders = new java.util.HashMap<String, Object>();
        // set key id to public key algorithm in protected headers
        protectedHeaders.put("kid", publicKey.alg.toString());
        // set jwk as a protected header
        protectedHeaders.put("jwk", publicKeyJwk.toJSONObject());

        try {
            ByteArrayOutputStream aggregateHash = Manifest.computeAggregateHash(manifest.encryptionInformation.integrityInformation.segments, manifest.payload.isEncrypted);
            boolean hexEncodeRootAndSegmentHashes = manifest.tdfVersion == null || manifest.tdfVersion.isEmpty();
            Manifest.Assertion.HashValues hashValues = Manifest.Assertion.calculateAssertionHashValues(aggregateHash, assertion, hexEncodeRootAndSegmentHashes);
            try {
                assertion.sign(hashValues, privateKey, Optional.of(protectedHeaders));
            } catch (KeyLengthException e) {
                throw new SDK.AssertionException("error signing assertion hash", assertion.id);
            }
        } catch (IOException e) {
            throw new SDK.AssertionException("error calculating assertion hash", assertion.id);
        }

        return assertion;
    }
}
