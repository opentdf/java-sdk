package io.opentdf.platform.sdk;

import java.util.Optional;

/**
 * Why an assertion, or the manifest that carries it, was rejected. Every
 * {@link SDK.AssertionFailureException} carries exactly one of these.
 * <p>
 * The {@link #code() codes} are the stable strings from Section 9 of the ZTDF assertions
 * specification. They are shared with the other OpenTDF SDKs and appear in error messages as
 * {@code reason=<code>}, so tools can match on them.
 */
public enum AssertionFailureReason {
    /** The manifest is not I-JSON: invalid UTF-8, a lone surrogate, a noncharacter, or an out-of-range number. */
    INVALID_JSON("invalid-json"),
    /** An object in the manifest has two members with the same name, compared after decoding escapes. */
    DUPLICATE_MEMBER("duplicate-member"),
    /** An object has a case variant of a modelled member name, such as {@code ID} or {@code Assertions}. */
    AMBIGUOUS_MEMBER("ambiguous-member"),
    /** The assertion's {@code id} is missing, empty, or not a JSON string. */
    INVALID_ID("invalid-id"),
    /** The assertion's {@code statement} is not an object, or its {@code value} is neither a string nor an object. */
    INVALID_STATEMENT("invalid-statement"),
    /** The {@code binding} is missing or malformed, has both binding forms or neither, or its JWS is malformed. */
    INVALID_BINDING("invalid-binding"),
    /** The binding uses an unknown {@code method}, or is a binding object this SDK does not support. */
    UNSUPPORTED_BINDING("unsupported-binding"),
    /** The JWS {@code alg} is missing, {@code none}, or not supported by this SDK. */
    UNSUPPORTED_ALGORITHM("unsupported-algorithm"),
    /** The JWS {@code alg} differs from the algorithm of the selected verification key. */
    ALGORITHM_MISMATCH("algorithm-mismatch"),
    /** An embedded {@code jwk} or {@code x5c} is symmetric, private, malformed, contradictory, or present in HMAC mode. */
    INVALID_EMBEDDED_KEY("invalid-embedded-key"),
    /** An embedded {@code jwk} or {@code x5c} does not match the selected verification key. */
    SIGNER_NOT_PERMITTED("signer-not-permitted"),
    /** The binding signature does not verify under the selected key. */
    SIGNATURE_INVALID("signature-invalid"),
    /** The signed {@code assertionHash} or {@code assertionSig} does not match the recomputed value. */
    BINDING_MISMATCH("binding-mismatch"),
    /** A configured verification key is empty, of the wrong type for its algorithm, or otherwise unusable. */
    CONFIGURATION_ERROR("configuration-error");

    private final String code;

    AssertionFailureReason(String code) {
        this.code = code;
    }

    /** The stable reason string, for example {@code signer-not-permitted}. */
    public String code() {
        return code;
    }

    /** The reason with the given {@link #code() code}, if there is one. */
    public static Optional<AssertionFailureReason> fromCode(String code) {
        for (AssertionFailureReason reason : values()) {
            if (reason.code.equals(code)) {
                return Optional.of(reason);
            }
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return code;
    }
}
