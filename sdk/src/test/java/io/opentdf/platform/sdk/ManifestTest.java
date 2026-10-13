package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ManifestTest {
    private static final long SEGMENT_SIZE_DEFAULT = 1048576;
    private static final long ENCRYPTED_SEGMENT_SIZE_DEFAULT = 1048604;

    @Test
    void testManifestMarshalAndUnMarshal() {
        String kManifestJsonFromTDF = "{\n" +
                "  \"encryptionInformation\": {\n" +
                "    \"integrityInformation\": {\n" +
                "      \"encryptedSegmentSizeDefault\": 1048604,\n" +
                "      \"rootSignature\": {\n" +
                "        \"alg\": \"HS256\",\n" +
                "        \"sig\": \"N2Y1ZjJlYWE4N2EzNjc2Nzc3NzgxNGU2ZGE1NmI4NDNhZTI5ZWY5NDc2OGI1ZTMzYTIyMTU4MDBlZTY3NzQzNA==\"\n" +
                "      },\n" +
                "      \"segmentHashAlg\": \"GMAC\",\n" +
                "      \"segmentSizeDefault\": 1048576,\n" +
                "      \"segments\": [\n" +
                "        {\n" +
                "          \"encryptedSegmentSize\": 41,\n" +
                "          \"hash\": \"ZWEyZTkwYjZiZThmYWZhNzg5ZmNjOWIyZTA2Njg5OTQ=\",\n" +
                "          \"segmentSize\": 1048576\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"keyAccess\": [\n" +
                "      {\n" +
                "        \"policyBinding\": {\n" +
                "          \"alg\": \"HS256\",\n" +
                "          \"hash\": \"YTgzNThhNzc5NWRhMjdjYThlYjk4ZmNmODliNzc2Y2E5ZmZiZDExZDQ3OTM5ODFjZTRjNmE3MmVjOTUzZTFlMA==\"\n" +
                "        },\n" +
                "        \"protocol\": \"kas\",\n" +
                "        \"type\": \"wrapped\",\n" +
                "        \"url\": \"http://localhost:65432/kas\",\n" +
                "        \"wrappedKey\": \"dJ3PdscXWvLv/juSkL7EMhl4lgLSBfI9EeoG2ct6NeSwPkPm/ieMF6ryDQjGeqZttoLlx2qBCVpik/BooGd/FtpYMIF/7a5RFTJ3G+o4Lww/zG6zIgV2APEPO+Gp7ORlFyMNJfn6Tj8ChTweKBqfXEXLihTV6sTZFtsWjdV96Z4KXbLe8tGpkXBpUAsSlmjcDJ920vrqnp3dvt2GwfmAiRWYCMXxnqUECqN5kVXMJywcvHatv2ZJSA/ixjDOrix+MocDJ69K/yFA17DXgfjf5X4SLyS0XgaZcXsdACBb+ogBlPw6vAbBrAyqI0Vi1msMRYNDS+FTl1yWEXl1HpyyCw==\"\n" +
                "      }\n" +
                "    ],\n" +
                "    \"method\": {\n" +
                "      \"algorithm\": \"AES-256-GCM\",\n" +
                "      \"isStreamable\": true,\n" +
                "      \"iv\": \"tozen81HLtZktNOP\"\n" +
                "    },\n" +
                "    \"policy\": \"eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJiNTM3MDllMy03NmE3LTRmYzctOGEwZi1mZDBhNjcyNmVhM2YifQ==\",\n" +
                "    \"type\": \"split\"\n" +
                "  },\n" +
                "  \"payload\": {\n" +
                "    \"isEncrypted\": true,\n" +
                "    \"mimeType\": \"application/octet-stream\",\n" +
                "    \"protocol\": \"zip\",\n" +
                "    \"type\": \"reference\",\n" +
                "    \"url\": \"0.payload\"\n" +
                "  }\n" +
                "}";

        Manifest manifest = Manifest.readManifest(kManifestJsonFromTDF);

        // Test payload
        assertEquals(manifest.payload.url, "0.payload");
        assertThat(manifest.payload.isEncrypted).isTrue();

        // Test encryptionInformation
        assertEquals(manifest.encryptionInformation.keyAccessType, "split");
        assertEquals(manifest.encryptionInformation.keyAccessObj.size(), 1);

        List<Manifest.KeyAccess> keyAccess = manifest.encryptionInformation.keyAccessObj;
        assertEquals(keyAccess.get(0).keyType, "wrapped");
        assertEquals(keyAccess.get(0).protocol, "kas");
        assertEquals(Manifest.PolicyBinding.class, keyAccess.get(0).policyBinding.getClass());
        var policyBinding = (Manifest.PolicyBinding) keyAccess.get(0).policyBinding;
        assertEquals(policyBinding.alg, "HS256");
        assertEquals(policyBinding.hash, "YTgzNThhNzc5NWRhMjdjYThlYjk4ZmNmODliNzc2Y2E5ZmZiZDExZDQ3OTM5ODFjZTRjNmE3MmVjOTUzZTFlMA==");
        assertEquals(manifest.encryptionInformation.method.algorithm, "AES-256-GCM");
        assertEquals(manifest.encryptionInformation.integrityInformation.rootSignature.algorithm, "HS256");
        assertEquals(manifest.encryptionInformation.integrityInformation.segmentHashAlg, "GMAC");
        assertEquals(manifest.encryptionInformation.integrityInformation.segments.get(0).segmentSize, 1048576);

        var serialized = Manifest.toJson(manifest);
        var deserializedAgain = Manifest.readManifest(serialized);

        assertEquals(manifest, deserializedAgain, "something changed when we deserialized -> serialized -> deserialized");
    }

    @Test
    void testAssertionNull() {
        String kManifestJsonFromTDF = "{\n" +
                "  \"encryptionInformation\": {\n" +
                "    \"integrityInformation\": {\n" +
                "      \"encryptedSegmentSizeDefault\": 1048604,\n" +
                "      \"rootSignature\": {\n" +
                "        \"alg\": \"HS256\",\n" +
                "        \"sig\": \"N2Y1ZjJlYWE4N2EzNjc2Nzc3NzgxNGU2ZGE1NmI4NDNhZTI5ZWY5NDc2OGI1ZTMzYTIyMTU4MDBlZTY3NzQzNA==\"\n" +
                "      },\n" +
                "      \"segmentHashAlg\": \"GMAC\",\n" +
                "      \"segmentSizeDefault\": 1048576,\n" +
                "      \"segments\": [\n" +
                "        {\n" +
                "          \"encryptedSegmentSize\": 41,\n" +
                "          \"hash\": \"ZWEyZTkwYjZiZThmYWZhNzg5ZmNjOWIyZTA2Njg5OTQ=\",\n" +
                "          \"segmentSize\": 1048576\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"keyAccess\": [\n" +
                "      {\n" +
                "        \"policyBinding\": {\n" +
                "          \"alg\": \"HS256\",\n" +
                "          \"hash\": \"YTgzNThhNzc5NWRhMjdjYThlYjk4ZmNmODliNzc2Y2E5ZmZiZDExZDQ3OTM5ODFjZTRjNmE3MmVjOTUzZTFlMA==\"\n" +
                "        },\n" +
                "        \"protocol\": \"kas\",\n" +
                "        \"type\": \"wrapped\",\n" +
                "        \"url\": \"http://localhost:65432/kas\",\n" +
                "        \"wrappedKey\": \"dJ3PdscXWvLv/juSkL7EMhl4lgLSBfI9EeoG2ct6NeSwPkPm/ieMF6ryDQjGeqZttoLlx2qBCVpik/BooGd/FtpYMIF/7a5RFTJ3G+o4Lww/zG6zIgV2APEPO+Gp7ORlFyMNJfn6Tj8ChTweKBqfXEXLihTV6sTZFtsWjdV96Z4KXbLe8tGpkXBpUAsSlmjcDJ920vrqnp3dvt2GwfmAiRWYCMXxnqUECqN5kVXMJywcvHatv2ZJSA/ixjDOrix+MocDJ69K/yFA17DXgfjf5X4SLyS0XgaZcXsdACBb+ogBlPw6vAbBrAyqI0Vi1msMRYNDS+FTl1yWEXl1HpyyCw==\"\n" +
                "      }\n" +
                "    ],\n" +
                "    \"method\": {\n" +
                "      \"algorithm\": \"AES-256-GCM\",\n" +
                "      \"isStreamable\": true,\n" +
                "      \"iv\": \"tozen81HLtZktNOP\"\n" +
                "    },\n" +
                "    \"policy\": \"eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJiNTM3MDllMy03NmE3LTRmYzctOGEwZi1mZDBhNjcyNmVhM2YifQ==\",\n" +
                "    \"type\": \"split\"\n" +
                "  },\n" +
                "  \"payload\": {\n" +
                "    \"isEncrypted\": true,\n" +
                "    \"mimeType\": \"application/octet-stream\",\n" +
                "    \"protocol\": \"zip\",\n" +
                "    \"type\": \"reference\",\n" +
                "    \"url\": \"0.payload\"\n" +
                "  },\n" +
                "   \"assertions\": null\n"+
                "}";

        Manifest manifest = Manifest.readManifest(kManifestJsonFromTDF);

        // Test payload for sanity check
        assertEquals(manifest.payload.url, "0.payload");
        assertThat(manifest.payload.isEncrypted).isTrue();
        // Test assertion deserialization
        assertThat(manifest.assertions).isNotNull();
        assertEquals(manifest.assertions.size(), 0);
    }

    /** A minimal but valid manifest wrapped around whatever {@code segments} array you give it. */
    private static String manifestWithSegments(String segmentsJson) {
        return manifestWithSegments(segmentsJson,
                "      \"encryptedSegmentSizeDefault\": " + ENCRYPTED_SEGMENT_SIZE_DEFAULT + ",\n"
                        + "      \"segmentSizeDefault\": " + SEGMENT_SIZE_DEFAULT + ",\n");
    }

    /** As {@link #manifestWithSegments(String)}, but with the two default declarations spelled out. */
    private static String manifestWithSegments(String segmentsJson, String defaultsJson) {
        return "{\n" +
                "  \"encryptionInformation\": {\n" +
                "    \"integrityInformation\": {\n" +
                defaultsJson +
                "      \"rootSignature\": { \"alg\": \"HS256\", \"sig\": \"c2ln\" },\n" +
                "      \"segmentHashAlg\": \"GMAC\",\n" +
                "      \"segments\": [" + segmentsJson + "]\n" +
                "    },\n" +
                "    \"keyAccess\": [ { \"protocol\": \"kas\", \"type\": \"wrapped\"," +
                " \"url\": \"http://localhost:65432/kas\", \"wrappedKey\": \"a2V5\" } ],\n" +
                "    \"method\": { \"algorithm\": \"AES-256-GCM\", \"isStreamable\": true, \"iv\": \"aXY=\" },\n" +
                "    \"policy\": \"cG9saWN5\",\n" +
                "    \"type\": \"split\"\n" +
                "  },\n" +
                "  \"payload\": { \"isEncrypted\": true, \"protocol\": \"zip\"," +
                " \"type\": \"reference\", \"url\": \"0.payload\" }\n" +
                "}";
    }

    /**
     * web-sdk leaves {@code segmentSize} and {@code encryptedSegmentSize} out of a segment
     * whenever they equal the manifest level defaults. That is legal, and an absent one means
     * "the default" rather than zero -- see {@code IntegrityInformationAdapterFactory} in
     * {@link Manifest} for why.
     */
    @Test
    void testAbsentSegmentSizesFallBackToTheManifestDefaults() {
        Manifest manifest = Manifest.readManifest(manifestWithSegments(
                "{ \"hash\": \"aGFzaDA=\" },"
                        + "{ \"hash\": \"aGFzaDE=\", \"segmentSize\": 12 },"
                        + "{ \"hash\": \"aGFzaDI=\", \"segmentSize\": 3, \"encryptedSegmentSize\": 31 }"));

        var segments = manifest.encryptionInformation.integrityInformation.segments;
        assertThat(segments).hasSize(3);

        assertThat(segments.get(0).segmentSize).isEqualTo(SEGMENT_SIZE_DEFAULT);
        assertThat(segments.get(0).encryptedSegmentSize).isEqualTo(ENCRYPTED_SEGMENT_SIZE_DEFAULT);

        assertThat(segments.get(1).segmentSize).isEqualTo(12);
        assertThat(segments.get(1).encryptedSegmentSize).isEqualTo(ENCRYPTED_SEGMENT_SIZE_DEFAULT);

        assertThat(segments.get(2).segmentSize).isEqualTo(3);
        assertThat(segments.get(2).encryptedSegmentSize).isEqualTo(31);

        // and the values we filled in survive a round trip through the serializer
        assertEquals(manifest, Manifest.readManifest(Manifest.toJson(manifest)));
    }

    /**
     * An explicit zero is a value rather than an absent key, so parsing leaves it alone; silently
     * rewriting it to the default would hide a corrupt manifest. {@code TDF.Reader} is what
     * rejects a zero {@code encryptedSegmentSize}, in
     * {@code TDFTest#testZeroLengthSegmentIsRejectedWithAClearError}. A zero {@code segmentSize}
     * is not checked anywhere, because nothing on the read path consumes it.
     */
    @Test
    void testExplicitZeroSegmentSizeIsNotTreatedAsAbsent() {
        Manifest manifest = Manifest.readManifest(manifestWithSegments(
                "{ \"hash\": \"aGFzaDA=\", \"segmentSize\": 0, \"encryptedSegmentSize\": 0 }"));

        var segment = manifest.encryptionInformation.integrityInformation.segments.get(0);
        assertThat(segment.segmentSize).isZero();
        assertThat(segment.encryptedSegmentSize).isZero();
    }

    /**
     * An explicit {@code null} carries no value, so unlike an explicit zero it is treated as
     * absent and picks up the default.
     */
    @Test
    void testNullSegmentSizeIsTreatedAsAbsent() {
        Manifest manifest = Manifest.readManifest(manifestWithSegments(
                "{ \"hash\": \"aGFzaDA=\", \"segmentSize\": null, \"encryptedSegmentSize\": null }"));

        var segment = manifest.encryptionInformation.integrityInformation.segments.get(0);
        assertThat(segment.segmentSize).isEqualTo(SEGMENT_SIZE_DEFAULT);
        assertThat(segment.encryptedSegmentSize).isEqualTo(ENCRYPTED_SEGMENT_SIZE_DEFAULT);
    }

    /**
     * With no defaults declared there is nothing to fall back to, so the segments keep their
     * zeroes rather than the fixup inventing a size. {@code TDF.loadTDF} is what rejects such a
     * manifest, when it checks the two defaults against each other.
     */
    @Test
    void testAbsentDefaultsLeaveSegmentSizesAtZero() {
        Manifest manifest = Manifest.readManifest(
                manifestWithSegments("{ \"hash\": \"aGFzaDA=\" }", ""));

        var segment = manifest.encryptionInformation.integrityInformation.segments.get(0);
        assertThat(segment.segmentSize).isZero();
        assertThat(segment.encryptedSegmentSize).isZero();
    }

    @Test
    void testReadingManifestWithObjectStatementValue() throws IOException {
        final Manifest manifest;
        try (var mStream = getClass().getResourceAsStream("/io.opentdf.platform.sdk.TestData/manifest-with-object-statement-value.json")) {
            assert mStream != null;
            var manifestJson = new String(mStream.readAllBytes(), StandardCharsets.UTF_8);
            manifest = Manifest.readManifest(manifestJson);
        }

        assertThat(manifest.assertions).hasSize(2);

        var statementValStr = manifest.assertions.get(0).statement.value;
        var statementVal = new Gson().fromJson(statementValStr, Map.class);
        assertThat(statementVal).isEqualTo(
                Map.of("ocl",
                        Map.of("pol", "2ccf11cb-6c9a-4e49-9746-a7f0a295945d",
                                "cls", "SECRET",
                                "catl", List.of(
                                        Map.of(
                                                "type", "P",
                                                "name", "Releasable To",
                                                "vals", List.of("usa")
                                        )
                                ),
                                "dcr", "2024-12-17T13:00:52Z"
                                ),
                        "context", Map.of("@base", "urn:nato:stanag:5636:A:1:elements:json")
                        )
        );
    }

    /**
     * A minimal but valid manifest with extra members spliced into the {@code payload} object
     * and into the manifest root. Each extra, when not empty, must begin with a comma.
     */
    private static String manifestWithExtras(String payloadExtra, String rootExtra) {
        return "{\n" +
                "  \"encryptionInformation\": {\n" +
                "    \"integrityInformation\": {\n" +
                "      \"encryptedSegmentSizeDefault\": " + ENCRYPTED_SEGMENT_SIZE_DEFAULT + ",\n" +
                "      \"segmentSizeDefault\": " + SEGMENT_SIZE_DEFAULT + ",\n" +
                "      \"rootSignature\": { \"alg\": \"HS256\", \"sig\": \"c2ln\" },\n" +
                "      \"segmentHashAlg\": \"GMAC\",\n" +
                "      \"segments\": [ { \"hash\": \"aGFzaDA=\" } ]\n" +
                "    },\n" +
                "    \"keyAccess\": [ { \"protocol\": \"kas\", \"type\": \"wrapped\"," +
                " \"url\": \"http://localhost:65432/kas\", \"wrappedKey\": \"a2V5\" } ],\n" +
                "    \"method\": { \"algorithm\": \"AES-256-GCM\", \"isStreamable\": true, \"iv\": \"aXY=\" },\n" +
                "    \"policy\": \"cG9saWN5\",\n" +
                "    \"type\": \"split\"\n" +
                "  },\n" +
                "  \"payload\": { \"isEncrypted\": true, \"protocol\": \"zip\"," +
                " \"type\": \"reference\", \"url\": \"0.payload\"" + payloadExtra + " }" +
                rootExtra + "\n" +
                "}";
    }

    static Stream<Arguments> specVersionCases() {
        return Stream.of(
                Arguments.of("schemaVersion at root", "", ",\"schemaVersion\":\"4.3.0\"", "4.3.0"),
                // where the spec prose documents it, and where web-sdk writes it
                Arguments.of("tdf_spec_version at root", "", ",\"tdf_spec_version\":\"4.3.0\"", "4.3.0"),
                // where revisions of the JSON schema declared it in error
                Arguments.of("tdf_spec_version under payload", ",\"tdf_spec_version\":\"4.3.0\"", "", "4.3.0"),
                Arguments.of("schemaVersion wins over payload tdf_spec_version",
                        ",\"tdf_spec_version\":\"4.2.0\"", ",\"schemaVersion\":\"4.3.0\"", "4.3.0"),
                Arguments.of("schemaVersion wins over root tdf_spec_version, whatever the key order",
                        "", ",\"tdf_spec_version\":\"4.2.0\",\"schemaVersion\":\"4.3.0\"", "4.3.0"),
                Arguments.of("schemaVersion wins over root tdf_spec_version",
                        "", ",\"schemaVersion\":\"4.3.0\",\"tdf_spec_version\":\"4.2.0\"", "4.3.0"),
                // the root is the placement with the better provenance, so it decides when the
                // two copies disagree
                Arguments.of("root tdf_spec_version wins over the payload copy",
                        ",\"tdf_spec_version\":\"4.2.0\"", ",\"tdf_spec_version\":\"4.3.0\"", "4.3.0"),
                // a null root copy is not a value, so the payload copy still applies
                Arguments.of("null root tdf_spec_version falls through to payload",
                        ",\"tdf_spec_version\":\"4.3.0\"", ",\"tdf_spec_version\":null", "4.3.0"),
                Arguments.of("numeric root tdf_spec_version falls through to payload",
                        ",\"tdf_spec_version\":\"4.3.0\"", ",\"tdf_spec_version\":430", "4.3.0"),
                Arguments.of("empty root tdf_spec_version falls through to payload",
                        ",\"tdf_spec_version\":\"4.3.0\"", ",\"tdf_spec_version\":\"\"", "4.3.0"),
                // an empty schemaVersion is not a value, so the fallback still applies
                Arguments.of("empty schemaVersion falls back to tdf_spec_version",
                        ",\"tdf_spec_version\":\"4.3.0\"", ",\"schemaVersion\":\"\"", "4.3.0"),
                Arguments.of("null schemaVersion falls back to tdf_spec_version",
                        "", ",\"schemaVersion\":null,\"tdf_spec_version\":\"4.3.0\"", "4.3.0"),
                Arguments.of("no version at all", "", "", null),
                // non-string values are schema validation's problem to report, not the decoder's
                // to choke on. the key is known in the wild carrying null
                Arguments.of("null tdf_spec_version is ignored", ",\"tdf_spec_version\":null", "", null),
                Arguments.of("numeric tdf_spec_version is ignored", ",\"tdf_spec_version\":430", "", null),
                Arguments.of("boolean tdf_spec_version is ignored", "", ",\"tdf_spec_version\":true", null),
                Arguments.of("object tdf_spec_version is ignored",
                        ",\"tdf_spec_version\":{\"major\":4}", ",\"tdf_spec_version\":{\"major\":4}", null),
                Arguments.of("array tdf_spec_version is ignored", ",\"tdf_spec_version\":[\"4.3.0\"]", "", null));
    }

    /**
     * {@code schemaVersion} is the name of the spec-version field. {@code tdf_spec_version} is a
     * non-aligned name that entered some specification drafts and some older OpenTDF documentation
     * in error; it is read, at the root and then under {@code payload}, only so that files written
     * with it stay usable.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("specVersionCases")
    void testSpecVersionIsReadFromAllThreePlaces(String name, String payloadExtra, String rootExtra, String want) {
        Manifest manifest = Manifest.readManifest(manifestWithExtras(payloadExtra, rootExtra));

        assertThat(manifest.tdfVersion).isEqualTo(want);

        // the version lookup must not disturb anything else in the document
        assertThat(manifest.payload.url).isEqualTo("0.payload");
        assertThat(manifest.payload.isEncrypted).isTrue();
        assertThat(manifest.encryptionInformation.keyAccessType).isEqualTo("split");
        assertThat(manifest.encryptionInformation.policy).isEqualTo("cG9saWN5");
        var integrityInformation = manifest.encryptionInformation.integrityInformation;
        assertThat(integrityInformation.segmentHashAlg).isEqualTo("GMAC");
        assertThat(integrityInformation.rootSignature.signature).isEqualTo("c2ln");
        // and the segment-size fixup, which lives in its own adapter, still runs
        assertThat(integrityInformation.segments.get(0).encryptedSegmentSize).isEqualTo(ENCRYPTED_SEGMENT_SIZE_DEFAULT);
    }

    /**
     * The writer names the field {@code schemaVersion} and never the non-aligned
     * {@code tdf_spec_version}, at the root or under {@code payload}. Reading a manifest that
     * used the non-aligned name and writing it back out therefore normalizes the name rather
     * than propagating it.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("nonAlignedPlacements")
    void testRoundTripEmitsSchemaVersionOnly(String name, String payloadExtra, String rootExtra) {
        Manifest manifest = Manifest.readManifest(manifestWithExtras(payloadExtra, rootExtra));
        assertThat(manifest.tdfVersion).isEqualTo("4.3.0");

        var written = JsonParser.parseString(Manifest.toJson(manifest)).getAsJsonObject();
        assertThat(written.get("schemaVersion").getAsString()).isEqualTo("4.3.0");
        assertThat(written.has("tdf_spec_version")).isFalse();
        assertThat(written.getAsJsonObject("payload").has("tdf_spec_version")).isFalse();

        assertEquals(manifest, Manifest.readManifest(written.toString()));
    }

    static Stream<Arguments> nonAlignedPlacements() {
        return Stream.of(
                Arguments.of("root", "", ",\"tdf_spec_version\":\"4.3.0\""),
                Arguments.of("payload", ",\"tdf_spec_version\":\"4.3.0\"", ""));
    }
}
