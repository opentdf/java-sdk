package io.opentdf.platform.sdk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The manifest reader applies the JSON profile of spec Section 3 to the whole manifest, before
 * any typed field or JSON tree can drop one of two duplicates, and whether or not assertions are
 * verified later.
 */
class StrictManifestParsingTest {

    private static String json(String singleQuoted) {
        return singleQuoted.replace('\'', '"');
    }

    /** A minimal valid manifest with {@code rootExtra} (which must start with a comma) spliced in. */
    static String manifest(String rootExtra) {
        return json("{'encryptionInformation':{'integrityInformation':{'encryptedSegmentSizeDefault':1048604,"
                + "'segmentSizeDefault':1048576,'rootSignature':{'alg':'HS256','sig':'c2ln'},'segmentHashAlg':'GMAC',"
                + "'segments':[{'hash':'aGFzaDA=','segmentSize':4,'encryptedSegmentSize':32}]},"
                + "'keyAccess':[{'protocol':'kas','type':'wrapped','url':'http://localhost:65432/kas','wrappedKey':'a2V5'}],"
                + "'method':{'algorithm':'AES-256-GCM','isStreamable':true,'iv':'aXY='},'policy':'cG9saWN5','type':'split'},"
                + "'payload':{'isEncrypted':true,'protocol':'zip','type':'reference','url':'0.payload'}"
                + rootExtra + "}");
    }

    static String withAssertions(String assertions) {
        return manifest(",'assertions':" + assertions);
    }

    static Stream<Arguments> rejectedManifests() {
        return Stream.of(
                // duplicates anywhere, including outside the assertions, and escaped spellings
                Arguments.of(manifest(",'payload':{}"), AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of(manifest(",'\\u0070ayload':{}"), AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of(manifest(",'extra':{'a':[{'b':1,'b':2}]}"), AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of(withAssertions("[]").replace("\"url\":\"0.payload\"", "\"url\":\"0.payload\",\"url\":\"x\""),
                        AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of(manifest(",'assertions':[],'assertions':[]"), AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of(withAssertions("[{'id':'a','id':'b'}]"), AssertionFailureReason.DUPLICATE_MEMBER, null),
                Arguments.of(withAssertions("[{'id':'a','statement':{'format':'x','format':'y'}}]"),
                        AssertionFailureReason.DUPLICATE_MEMBER, "a"),
                // case variants of modelled names, even with the exact name absent
                Arguments.of(manifest(",'assertions':[],'Assertions':[]"), AssertionFailureReason.AMBIGUOUS_MEMBER, null),
                Arguments.of(manifest(",'ASSERTIONS':[]"), AssertionFailureReason.AMBIGUOUS_MEMBER, null),
                Arguments.of(withAssertions("[{'id':'classification','ID':'system-metadata'}]"),
                        AssertionFailureReason.AMBIGUOUS_MEMBER, "classification"),
                Arguments.of(withAssertions("[{'ID':'system-metadata'}]"), AssertionFailureReason.AMBIGUOUS_MEMBER, null),
                Arguments.of(withAssertions("[{'id':'a','binding':{'Signature':'x'}}]"),
                        AssertionFailureReason.AMBIGUOUS_MEMBER, "a"),
                // non-I-JSON content inside an assertion
                Arguments.of(withAssertions("[{'id':'a','statement':{'value':'\\uDEAD'}}]"),
                        AssertionFailureReason.INVALID_JSON, "a"),
                Arguments.of(withAssertions("[{'id':'a','n':1e400}]"), AssertionFailureReason.INVALID_JSON, "a"),
                // later assertions are checked too, and report their own id
                Arguments.of(withAssertions("[{'id':'a'},{'id':'b','Id':'c'}]"), AssertionFailureReason.AMBIGUOUS_MEMBER, "b"));
    }

    @ParameterizedTest
    @MethodSource("rejectedManifests")
    void rejects(String manifest, AssertionFailureReason reason, String id) {
        assertThatThrownBy(() -> Manifest.readManifest(manifest))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(reason);
                    assertThat(e.getAssertionId()).isEqualTo(id);
                    assertThat(e).hasMessageContaining("reason=" + reason.code());
                });
        // the manifest-only check used by the shared vectors agrees
        assertThatThrownBy(() -> Manifest.checkManifestJson(manifest))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(reason));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            // the I-JSON checks are required only inside assertions
            ",'extra':{'n':1e400,'s':'\\uDEAD'}",
            // case variants are only checked at the four modelled levels
            ",'payload2':{'Assertions':1},'assertions':[{'id':'a','statement':{'value':{'ID':1}},'extensions':{'Binding':1}}]",
            // values the typed model coerces or ignores still parse
            ",'assertions':[{'id':5,'type':{},'binding':'not an object'}]"
    })
    void accepts(String rootExtra) {
        var manifest = manifest(rootExtra);
        assertThatCode(() -> Manifest.readManifest(manifest)).doesNotThrowAnyException();
        assertThatCode(() -> Manifest.checkManifestJson(manifest)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {",'a':NaN", ",'a':'x'//", ",'a':'x',", ",a:1", ",'a':'\\x'", "} {"})
    void readsOnlyStrictJson(String rootExtra) {
        var manifest = manifest(rootExtra);
        assertThatThrownBy(() -> Manifest.readManifest(manifest)).isInstanceOf(com.google.gson.JsonParseException.class);
    }

    @Test
    void reportsInvalidUtf8AsInvalidJson() throws IOException {
        var valid = withAssertions("[{'id':'a','statement':{'value':'XY'}}]").getBytes(StandardCharsets.UTF_8);
        var invalid = valid.clone();
        int at = new String(valid, StandardCharsets.UTF_8).indexOf("XY");
        invalid[at] = (byte) 0xC3; // a lead byte followed by an ASCII byte is malformed
        assertThatCode(() -> SDK.readManifest(new SeekableInMemoryByteChannel(tdfWithManifest(valid))))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> SDK.readManifest(new SeekableInMemoryByteChannel(tdfWithManifest(invalid))))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_JSON));
    }

    @Test
    void reportsInvalidUtf8OutsideTheAssertionsAsInvalidJsonToo() throws IOException {
        var valid = manifest(",'extra':'XY'").getBytes(StandardCharsets.UTF_8);
        var invalid = valid.clone();
        invalid[new String(valid, StandardCharsets.UTF_8).indexOf("XY")] = (byte) 0xFF;
        assertThatThrownBy(() -> SDK.readManifest(new SeekableInMemoryByteChannel(tdfWithManifest(invalid))))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_JSON);
                    assertThat(e).hasMessageContaining("reason=invalid-json");
                });
    }

    static byte[] tdfWithManifest(byte[] manifest) throws IOException {
        var out = new ByteArrayOutputStream();
        var writer = new TDFWriter(out);
        try (var payload = writer.payload()) {
            payload.write(new byte[32]);
        }
        try (var manifestOut = writer.manifest()) {
            manifestOut.write(manifest);
        }
        writer.finish();
        return out.toByteArray();
    }

    @Test
    void keepsEachAssertionAsReceived() {
        var assertion = "{'id':'a','type':'handling','scope':'payload','appliesToState':null,"
                + "'statement':{'format':'json-structured','schema':'s','value':{'n':1.50,'ocl':{'cls':'SECRET'}},'extra':[1]},"
                + "'extensions':{'note':'coi'},'binding':{'method':'JWS','signature':'a.b.c'}}";
        var manifest = Manifest.readManifest(withAssertions("[" + assertion + "]"));
        var read = manifest.assertions.get(0);
        assertThat(read.id).isEqualTo("a");
        assertThat(read.statement.value).isEqualTo("{\"n\":1.50,\"ocl\":{\"cls\":\"SECRET\"}}");
        assertThat(read.binding.method).isEqualTo("JWS");

        String expectedHash = Manifest.Assertion.computeAssertionHash(json(assertion));
        assertThat(AssertionJson.hash(read.received())).isEqualTo(expectedHash);

        // serializing writes the assertion back as received, unmodelled members and nulls included
        var written = JsonParser.parseString(Manifest.toJson(manifest)).getAsJsonObject()
                .getAsJsonArray("assertions").get(0);
        assertThat(written).isEqualTo(JsonParser.parseString(json(assertion)));
        assertThat(Manifest.Assertion.computeAssertionHash(written.toString())).isEqualTo(expectedHash);

        // and so does the plain Gson the TDF writer uses
        var plain = JsonParser.parseString(new com.google.gson.Gson().toJson(manifest)).getAsJsonObject()
                .getAsJsonArray("assertions").get(0);
        assertThat(plain).isEqualTo(JsonParser.parseString(json(assertion)));
    }

    @Test
    void aChangedTypedFieldReplacesOnlyItsMember() throws IOException {
        var assertion = "{'id':'a','statement':{'format':'f','value':{'x':1},'extra':true},'extensions':{'note':'coi'}}";
        var manifest = Manifest.readManifest(withAssertions("[" + assertion + "]"));
        var read = manifest.assertions.get(0);
        read.statement.format = "g";
        read.scope = "tdo";

        JsonObject written = JsonParser.parseString(Manifest.toJson(manifest)).getAsJsonObject()
                .getAsJsonArray("assertions").get(0).getAsJsonObject();
        assertThat(written).isEqualTo(JsonParser.parseString(
                json("{'id':'a','statement':{'format':'g','value':{'x':1},'extra':true},'extensions':{'note':'coi'},'scope':'tdo'}")));
        assertThat(read.hash()).isEqualTo(Manifest.Assertion.computeAssertionHash(written.toString()));
        // the received object itself is never modified
        assertThat(AssertionJson.hash(read.received())).isEqualTo(Manifest.Assertion.computeAssertionHash(json(assertion)));
    }

    @Test
    void anAssertionBuiltInCodeSerializesItsNonNullFields() throws IOException {
        var assertion = new Manifest.Assertion();
        assertion.id = "a";
        assertion.type = "handling";
        assertion.statement = new AssertionConfig.Statement();
        assertion.statement.value = "{\"x\":1}";
        assertion.binding = new Manifest.Binding();
        assertion.binding.method = "jws";
        assertion.binding.signature = "a.b.c";

        var written = JsonParser.parseString(new com.google.gson.Gson().toJson(assertion));
        assertThat(written).isEqualTo(JsonParser.parseString(
                json("{'id':'a','type':'handling','statement':{'value':'{\\'x\\':1}'},'binding':{'method':'jws','signature':'a.b.c'}}")));
        assertThat(assertion.hash()).isEqualTo(Manifest.Assertion.computeAssertionHash(written.toString()));
    }

    @Test
    void nullAssertionsAreMalformed() {
        assertThatThrownBy(() -> Manifest.readManifest(withAssertions("[null]")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAByteOrderMark() throws IOException {
        var withBom = ("\uFEFF" + manifest("")).getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> SDK.readManifest(new SeekableInMemoryByteChannel(tdfWithManifest(withBom))))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_JSON));
        assertThatThrownBy(() -> Manifest.checkManifestJson("\uFEFF" + manifest("")))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_JSON));
        assertThatThrownBy(() -> Manifest.Assertion.computeAssertionHash("\uFEFF{\"id\":\"a\"}"))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_JSON));
        // a byte order mark is ordinary content anywhere else
        assertThatCode(() -> Manifest.readManifest(manifest(",'extra':'\uFEFF'"))).doesNotThrowAnyException();
    }

    static Stream<Arguments> wholeManifestCaseVariants() {
        String twoSegments = "[{\"hash\":\"aGFzaDA=\",\"segmentSize\":4,\"encryptedSegmentSize\":32},"
                + "{\"Hash\":\"aGFzaDE=\",\"segmentSize\":4,\"encryptedSegmentSize\":32}]";
        String manifest = manifest("");
        return Stream.of(
                // rule 1: a variant of a listed name, with the listed member absent
                Arguments.of("Payload at the root", manifest.replace("\"payload\":", "\"Payload\":")),
                Arguments.of("URL in a key access object", manifest.replace("\"url\":\"http", "\"URL\":\"http")),
                Arguments.of("SchemaVersion at the root", manifest(",'SchemaVersion':'4.3.0'")),
                Arguments.of("long s in segmentHashAlg", manifest.replace("\"segmentHashAlg\"", "\"\u017fegmentHashAlg\"")),
                Arguments.of("Hash in the second segment", manifest.replace(
                        "[{\"hash\":\"aGFzaDA=\",\"segmentSize\":4,\"encryptedSegmentSize\":32}]", twoSegments)),
                Arguments.of("ALG in a policy binding", manifest.replace("\"wrappedKey\":\"a2V5\"",
                        "\"wrappedKey\":\"a2V5\",\"policyBinding\":{\"ALG\":\"HS256\",\"hash\":\"aA==\"}")),
                Arguments.of("IV in the method", manifest.replace("\"iv\":", "\"IV\":")),
                Arguments.of("Sig in the root signature", manifest.replace("\"sig\":", "\"Sig\":")),
                Arguments.of("MimeType in the payload", manifest.replace("\"url\":\"0.payload\"",
                        "\"url\":\"0.payload\",\"MimeType\":\"text/plain\"")),
                Arguments.of("Policy in encryptionInformation", manifest.replace("\"policy\":", "\"Policy\":")),
                Arguments.of("KID in a key access object", manifest.replace("\"wrappedKey\"", "\"KID\":\"k\",\"wrappedKey\"")),
                Arguments.of("tdf_spec_Version in the payload", manifest.replace("\"url\":\"0.payload\"",
                        "\"url\":\"0.payload\",\"tdf_spec_Version\":\"4.3.0\"")),
                // rule 2: two names that are case variants of each other, neither listed
                Arguments.of("foo and Foo at the root", manifest(",'foo':1,'Foo':2")),
                Arguments.of("Extra and extra in a segment", manifest.replace("\"segmentSize\":4",
                        "\"segmentSize\":4,\"Extra\":1,\"extra\":2")),
                Arguments.of("IsStreamable with isStreamable",
                        manifest.replace("\"isStreamable\":true", "\"isStreamable\":true,\"IsStreamable\":true")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("wholeManifestCaseVariants")
    void rejectsCaseVariantsAtEveryModelledLevel(String name, String manifest) {
        assertThatThrownBy(() -> Manifest.readManifest(manifest))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.AMBIGUOUS_MEMBER));
        assertThatThrownBy(() -> Manifest.checkManifestJson(manifest))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.AMBIGUOUS_MEMBER));
    }

    static Stream<Arguments> caseVariantsOutsideTheModelledLevels() {
        String manifest = manifest("");
        return Stream.of(
                // the one legacy exception to rule 1
                Arguments.of("IsStreamable alone",
                        manifest.replace("\"isStreamable\":true", "\"IsStreamable\":true")),
                Arguments.of("case pairs inside statement.value",
                        withAssertions("[{'id':'a','statement':{'value':{'a':1,'A':2,'ID':3,'id':4}}}]")),
                Arguments.of("case pairs inside an unlisted member", manifest(",'extra':{'foo':1,'Foo':2,'Payload':3}")),
                Arguments.of("case pairs inside an unlisted member of a key access object",
                        manifest.replace("\"wrappedKey\"", "\"extra\":{\"a\":1,\"A\":2},\"wrappedKey\"")),
                Arguments.of("a dotless i is not a variant of id", withAssertions("[{'id':'a','\u0131d':'x'}]")),
                Arguments.of("a different length is not a variant", manifest(",'payloads':1,'Payloads2':2")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("caseVariantsOutsideTheModelledLevels")
    void acceptsCaseVariantsOutsideTheModelledLevels(String name, String manifest) {
        assertThatCode(() -> Manifest.readManifest(manifest)).doesNotThrowAnyException();
        assertThatCode(() -> Manifest.checkManifestJson(manifest)).doesNotThrowAnyException();
    }

    @Test
    void readsTheJava075GoldenTdfWithIsStreamable() throws IOException {
        // the xtest golden file, when this checkout sits next to opentdf/tests
        var golden = java.nio.file.Path.of("..", "..", "tests", "xtest", "golden",
                "xstext-java-v0.7.5-94b161d53-DSP2.0.2_and_2.0.3.tdf");
        org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.isRegularFile(golden),
                "golden TDF not available at " + golden.toAbsolutePath());
        try (var channel = java.nio.channels.FileChannel.open(golden)) {
            var manifest = SDK.readManifest(channel);
            assertThat(manifest.encryptionInformation.method.algorithm).isNotNull();
        }
        try (var reader = TDFReader.open(java.nio.channels.FileChannel.open(golden)).manifest()) {
            var text = new java.io.StringWriter();
            reader.transferTo(text);
            assertThat(text.toString()).contains("\"IsStreamable\"");
        }
    }

    @Test
    void longSegmentListsStayLinear() {
        var segments = new StringBuilder("[");
        for (int i = 0; i < 200_000; i++) {
            segments.append(i == 0 ? "" : ",").append("{\"hash\":\"aGFzaDA=\",\"segmentSize\":4,\"encryptedSegmentSize\":32}");
        }
        String manifest = manifest("").replace(
                "[{\"hash\":\"aGFzaDA=\",\"segmentSize\":4,\"encryptedSegmentSize\":32}]", segments.append("]"));
        long start = System.nanoTime();
        assertThat(Manifest.readManifest(manifest).encryptionInformation.integrityInformation.segments).hasSize(200_000);
        // generous: a quadratic check would take minutes here
        assertThat(java.time.Duration.ofNanos(System.nanoTime() - start)).isLessThan(java.time.Duration.ofSeconds(20));
    }
}
