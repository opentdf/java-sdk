package io.opentdf.platform.sdk;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link Manifest.Assertion#computeAssertionHash}: the hash input is the assertion as received,
 * minus only its top-level {@code binding} (spec Section 4), after the JSON profile checks of
 * Section 3.
 */
class AssertionHashTest {

    /** Single quotes stand in for double quotes, to keep the fixtures readable. */
    private static String json(String singleQuoted) {
        return singleQuoted.replace('\'', '"');
    }

    private static String sha256Hex(String text) throws Exception {
        return Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    /** The classification example of spec Section 4.4. */
    static JsonObject classificationAssertion() {
        var statement = new JsonObject();
        statement.addProperty("format", "json+stanag5636");
        statement.addProperty("schema", "urn:nato:stanag:5636:A:1:elements:json");
        statement.addProperty("value",
                "{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"dcr\":\"2024-10-21T20:47:36Z\"}}");
        var assertion = new JsonObject();
        assertion.addProperty("id", "classification");
        assertion.addProperty("type", "handling");
        assertion.addProperty("scope", "payload");
        assertion.addProperty("appliesToState", "unencrypted");
        assertion.add("statement", statement);
        return assertion;
    }

    /** The ACP 240-style example of spec Sections 2.2 and 4.4, with an object-valued label. */
    static JsonObject acp240Assertion() {
        var catl = new JsonObject();
        catl.addProperty("type", "P");
        catl.addProperty("name", "Releasable To");
        var vals = new JsonArray();
        vals.add("USA");
        catl.add("vals", vals);
        var catls = new JsonArray();
        catls.add(catl);
        var ocl = new JsonObject();
        ocl.addProperty("pol", "62c76c68-d73d-4628-8ccc-4c1e18118c22");
        ocl.addProperty("cls", "CONFIDENTIAL");
        ocl.add("catl", catls);
        ocl.addProperty("dcr", "2026-11-06T12:00:00Z");
        var context = new JsonObject();
        context.addProperty("@base", "urn:nato:stanag:5636:A:1:elements:json");
        var value = new JsonObject();
        value.add("@context", context);
        value.add("ocl", ocl);
        var statement = new JsonObject();
        statement.addProperty("format", "json-structured");
        statement.addProperty("schema", "urn:nato:stanag:5636:A:1:elements:json");
        statement.add("value", value);
        var assertion = new JsonObject();
        assertion.addProperty("id", "3f1c2d9e-8a4b-4c6d-9e0f-1a2b3c4d5e6f");
        assertion.addProperty("type", "handling");
        assertion.addProperty("scope", "payload");
        assertion.addProperty("appliesToState", "encrypted");
        assertion.add("statement", statement);
        return assertion;
    }

    @Test
    void matchesTheSpecWorkedExamples() {
        assertThat(Manifest.Assertion.computeAssertionHash(classificationAssertion().toString()))
                .isEqualTo("456d05d6a3f48a14aeee20c8d5f0429d07e5be3f1695fcec2dbc755cd9d64495");

        var withExtension = classificationAssertion();
        withExtension.add("extensions", JsonParser.parseString(json("{'hash':'deadbeef','note':'coi'}")));
        assertThat(Manifest.Assertion.computeAssertionHash(withExtension.toString()))
                .as("an unmodelled member is part of the hash")
                .isEqualTo("a7347ff1c718c0ee7e88558de64389d5e7194990eb6c78662d0bcd9cfb19c7ba");

        assertThat(Manifest.Assertion.computeAssertionHash(acp240Assertion().toString()))
                .as("an object-valued statement is hashed as an object")
                .isEqualTo("46853cb52912fd76f3ff90df3936158ee220b8e5973c5d02bb6e50f468596fba");
    }

    @Test
    void ignoresOnlyTheTopLevelBindingAndTheLayout() {
        var expected = Manifest.Assertion.computeAssertionHash(classificationAssertion().toString());

        var withBinding = classificationAssertion();
        withBinding.add("binding", JsonParser.parseString(json("{'method':'jws','signature':'a.b.c'}")));
        assertThat(Manifest.Assertion.computeAssertionHash(withBinding.toString())).isEqualTo(expected);

        var reordered = new JsonObject();
        reordered.add("statement", classificationAssertion().get("statement"));
        reordered.addProperty("type", "handling");
        reordered.addProperty("appliesToState", "unencrypted");
        reordered.addProperty("scope", "payload");
        reordered.addProperty("id", "classification");
        var spaced = new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(reordered);
        assertThat(spaced).contains("\n");
        assertThat(Manifest.Assertion.computeAssertionHash(spaced)).isEqualTo(expected);
    }

    @Test
    void hashesNestedMembersNamedLikeExcludedOnes() {
        var plain = classificationAssertion();
        var nested = classificationAssertion();
        nested.getAsJsonObject("statement").addProperty("hash", "x");
        nested.getAsJsonObject("statement").add("binding", JsonParser.parseString("{\"signingKey\":\"y\"}"));
        assertThat(Manifest.Assertion.computeAssertionHash(nested.toString()))
                .isNotEqualTo(Manifest.Assertion.computeAssertionHash(plain.toString()));
    }

    @Test
    void anExplicitNullIsHashed() {
        var withNull = classificationAssertion();
        withNull.add("appliesToState", com.google.gson.JsonNull.INSTANCE);
        var without = classificationAssertion();
        without.remove("appliesToState");
        assertThat(Manifest.Assertion.computeAssertionHash(withNull.toString()))
                .isNotEqualTo(Manifest.Assertion.computeAssertionHash(without.toString()));
    }

    static Stream<Arguments> canonicalForms() {
        return Stream.of(
                // numbers are IEEE 754 doubles in RFC 8785, printed the way ECMAScript prints them
                Arguments.of("{'id':'a','n':1E21}", "{'id':'a','n':1e+21}"),
                Arguments.of("{'id':'a','n':-0}", "{'id':'a','n':0}"),
                Arguments.of("{'id':'a','n':9007199254740993}", "{'id':'a','n':9007199254740992}"),
                Arguments.of("{'id':'a','n':1.0}", "{'id':'a','n':1}"),
                Arguments.of("{'id':'a','n':0.0000001}", "{'id':'a','n':1e-7}"),
                Arguments.of("{'id':'a','n':1e-400}", "{'id':'a','n':0}"),
                Arguments.of("{'id':'a','n':123456789012345680000}", "{'id':'a','n':123456789012345680000}"),
                // escapes are decoded, and only the RFC 8785 set is re-escaped
                Arguments.of("{'id':'\\u0061','s':'\\u00e9\\/\\u2028'}", "{'id':'a','s':'é/ '}"),
                Arguments.of("{'id':'a','s':'\\u001f\\b'}", "{'id':'a','s':'\\u001f\\b'}"),
                // keys sort by UTF-16 code unit, not by code point
                Arguments.of("{'ﬁ':2,'😀':1,'id':'a'}", "{'id':'a','😀':1,'ﬁ':2}"));
    }

    @ParameterizedTest
    @MethodSource("canonicalForms")
    void canonicalizesUnderRfc8785(String input, String canonical) throws Exception {
        assertThat(Manifest.Assertion.computeAssertionHash(json(input))).isEqualTo(sha256Hex(json(canonical)));
    }

    static Stream<Arguments> rejected() {
        return Stream.of(
                Arguments.of("{'id':'a','id':'b'}", AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of("{'id':'a','\\u0069d':'b'}", AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of("{'id':'a','x':1,'x':1}", AssertionFailureReason.DUPLICATE_MEMBER, "a"),
                Arguments.of("{'id':'a','statement':{'value':{'x':1,'x':2}}}", AssertionFailureReason.DUPLICATE_MEMBER, "a"),
                Arguments.of("{'id':'a','ID':'b'}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'Id':'b'}", AssertionFailureReason.AMBIGUOUS_MEMBER, null),
                Arguments.of("{'id':'a','Statement':{}}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'id':'a','APPLIESTOSTATE':'x'}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'id':'a','ſtatement':{}}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'id':'a','statement':{'Value':'x'}}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'id':'a','binding':{'Method':'jws','signature':'x'}}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'id':'a','binding':{'BDO':'x'}}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'id':'a','x':'\\uDEAD'}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','x':'\\uD83D'}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','\\uDEAD':1}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','x':'\\uFFFE'}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','x':'\\uFDD0'}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','x':'\\uD83F\\uDFFF'}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','statement':{'value':{'n':[1e400]}}}", AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of("{'id':'a','n':-1E400}", AssertionFailureReason.INVALID_JSON, "a"),
                // a bad id is never reported as the assertion's id
                Arguments.of("{'id':'\\uDEAD'}", AssertionFailureReason.INVALID_JSON, null),
                // the first failure in document order wins
                Arguments.of("{'id':'a','ID':1,'x':'\\uDEAD'}", AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                Arguments.of("{'x':'\\uDEAD','id':'a','id':'b'}", AssertionFailureReason.INVALID_JSON, null));
    }

    @ParameterizedTest
    @MethodSource("rejected")
    void rejectsWhatSection3Forbids(String input, AssertionFailureReason reason, String id) {
        assertThatThrownBy(() -> Manifest.Assertion.computeAssertionHash(json(input)))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(reason);
                    assertThat(e.getAssertionId()).isEqualTo(id);
                    assertThat(e).hasMessageContaining("reason=" + reason.code());
                    if (id != null) {
                        assertThat(e).hasMessageContaining("id: " + id);
                    }
                })
                .isInstanceOf(SDK.TamperException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // not a case variant under Go's EqualFold, so an ordinary unmodelled member
            "{'id':'a','ıd':'x'}",
            // the rule does not reach into statement values or unmodelled members
            "{'id':'a','statement':{'value':{'ID':1,'Value':2,'Binding':3}}}",
            "{'id':'a','extensions':{'Binding':1,'Statement':2}}",
            // a valid surrogate pair and a noncharacter-free astral code point are fine
            "{'id':'a','x':'\\uD83D\\uDE00'}",
            // no id at all is still hashable; the id is checked when the assertion is verified
            "{'type':'handling'}",
            "{}"
    })
    void acceptsWhatSection3Allows(String input) {
        assertThat(Manifest.Assertion.computeAssertionHash(json(input))).matches("[0-9a-f]{64}");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "[]", "\"x\"", "{", "{} {}", "{'id':'a',}", "{id:'a'}", "/*c*/{}", "{'id':'a'} x"})
    void rejectsTextThatIsNotOneStrictJsonObject(String input) {
        assertThatThrownBy(() -> Manifest.Assertion.computeAssertionHash(json(input)))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_JSON));
    }

    @Test
    void anUnmodelledMemberChangesTheHash() {
        var original = classificationAssertion();
        original.addProperty("note", "approved");
        var tampered = classificationAssertion();
        tampered.addProperty("note", "rejected");
        assertThat(Manifest.Assertion.computeAssertionHash(original.toString()))
                .isNotEqualTo(Manifest.Assertion.computeAssertionHash(tampered.toString()));
    }

    private static String message(String id, String detail) {
        return new SDK.AssertionFailureException(id, AssertionFailureReason.BINDING_MISMATCH, detail).getMessage();
    }

    @Test
    void idsAreRenderedSafelyInMessages() {
        var failure = new SDK.AssertionFailureException("a\nreason=verified", AssertionFailureReason.BINDING_MISMATCH, null);
        // the typed field keeps the exact id
        assertThat(failure.getAssertionId()).isEqualTo("a\nreason=verified");
        assertThat(failure.getMessage())
                .doesNotContain("\n")
                .contains("id: a\\nreason=verified")
                .endsWith(", reason=binding-mismatch");

        // C1 controls such as NEL, DEL, and other C0 controls are escaped JSON-style
        assertThat(message("a\u0085b\u007fc\u001bd\te", null))
                .contains("id: a\\u0085b\\u007fc\\u001bd\\te,");
        // a backslash is escaped, so escape-like text in an id cannot pass for an escape
        assertThat(message("a\\u000ab", null)).contains("id: a\\\\u000ab,");
        // text that looks like a reason stays part of the id, before the real reason
        assertThat(message("x, reason=signature-invalid", null))
                .endsWith("id: x, reason=signature-invalid, reason=binding-mismatch");
    }

    @Test
    void longIdsAndDetailsAreCut() {
        String id = "\uD83D\uDE00".repeat(100_000);
        var failure = new SDK.AssertionFailureException(id, AssertionFailureReason.BINDING_MISMATCH, "x".repeat(1_000_000));
        assertThat(failure.getAssertionId()).isEqualTo(id);
        String message = failure.getMessage();
        assertThat(message).contains("id: " + "\uD83D\uDE00".repeat(256) + "\u2026, reason=binding-mismatch: ")
                .endsWith("x".repeat(512) + "\u2026")
                .hasSizeLessThan(2_000);
        // an id of exactly the limit is not cut
        assertThat(message("y".repeat(256), null)).contains("id: " + "y".repeat(256) + ", reason=");
    }
}
