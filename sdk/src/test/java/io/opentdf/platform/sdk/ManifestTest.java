package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ManifestTest {
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

        Manifest manifest = Manifest.readManifest(new StringReader(kManifestJsonFromTDF));

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
        var deserializedAgain = Manifest.readManifest(new StringReader(serialized));

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

        Manifest manifest = Manifest.readManifest(new StringReader(kManifestJsonFromTDF));

        // Test payload for sanity check
        assertEquals(manifest.payload.url, "0.payload");
        assertThat(manifest.payload.isEncrypted).isTrue();
        // Test assertion deserialization
        assertThat(manifest.assertions).isNotNull();
        assertEquals(manifest.assertions.size(), 0);
    }

    @Test
    void testReadingManifestWithObjectStatementValue() throws IOException {
        final Manifest manifest;
        try (var mStream = getClass().getResourceAsStream("/io.opentdf.platform.sdk.TestData/manifest-with-object-statement-value.json")) {
            assert mStream != null;
            manifest = Manifest.readManifest(new InputStreamReader(mStream)) ;
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
}
