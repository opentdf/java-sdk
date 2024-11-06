package io.opentdf.platform.sdk;

import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Test;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ManifestTest {
    private static final Gson gson = new Gson();

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

        GsonBuilder gsonBuilder = new GsonBuilder();
        Gson gson = gsonBuilder.setPrettyPrinting().create();
        Manifest manifest = gson.fromJson(kManifestJsonFromTDF, Manifest.class);

        // Test payload
        assertEquals(manifest.payload.url, "0.payload");
        assertEquals(manifest.payload.isEncrypted, true);

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

        var serialized = gson.toJson(manifest);
        var deserializedAgain = gson.fromJson(serialized, Manifest.class);

        assertEquals(manifest, deserializedAgain, "something changed when we deserialized -> serialized -> deserialized");
    }

    @Test
    void testAssertionHasdh() {
        var assertionConfig = new AssertionConfig();
        assertionConfig.id = "424ff3a3-50ca-4f01-a2ae-ef851cd3cac0";
        assertionConfig.type = AssertionConfig.Type.HandlingAssertion;
        assertionConfig.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig.appliesToState = AssertionConfig.AppliesToState.Encrypted;
        assertionConfig.statement = new AssertionConfig.Statement();
        assertionConfig.statement.format = "json+stanag5636";
        assertionConfig.statement.schema = "urn:nato:stanag:5636:A:1:elements:json";
        assertionConfig.statement.value = "{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"catl\":[{\"type\":\"P\",\"name\":\"Releasable To\",\"vals\":[\"usa\"]}],\"dcr\":\"2024-10-21T20:47:36Z\"},\"context\":{\"@base\":\"urn:nato:stanag:5636:A:1:elements:json\"}}";

        var assertion = new Manifest.Assertion();
        assertion.id = assertionConfig.id;
        assertion.type = assertionConfig.type.toString();
        assertion.scope = assertionConfig.scope.toString();
        assertion.statement = assertionConfig.statement;
        assertion.appliesToState = assertionConfig.appliesToState.toString();

        final String jsonCanonicalizerString = "{\"appliesToState\":\"encrypted\",\"id\":\"424ff3a3-50ca-4f01-a2ae-ef851cd3cac0\",\"scope\":\"tdo\",\"statement\":{\"format\":\"json+stanag5636\",\"schema\":\"urn:nato:stanag:5636:A:1:elements:json\",\"value\":\"{\\\"ocl\\\":{\\\"pol\\\":\\\"62c76c68-d73d-4628-8ccc-4c1e18118c22\\\",\\\"cls\\\":\\\"SECRET\\\",\\\"catl\\\":[{\\\"type\\\":\\\"P\\\",\\\"name\\\":\\\"Releasable To\\\",\\\"vals\\\":[\\\"usa\\\"]}],\\\"dcr\\\":\\\"2024-10-21T20:47:36Z\\\"},\\\"context\\\":{\\\"@base\\\":\\\"urn:nato:stanag:5636:A:1:elements:json\\\"}}\"},\"type\":\"handling\"}";
        try {
            var assertionAsJson = gson.toJson(assertion);
            var jc = new JsonCanonicalizer(assertionAsJson);
            var assertionBytes = jc.getEncodedUTF8();
            String assertionString = new String(assertionBytes, StandardCharsets.UTF_8);
            assertEquals(jsonCanonicalizerString, assertionString);
            //System.out.println("Encoded UTF-8: " + assertionString);

            var assertionHash = assertion.hash();
            assertEquals(assertionHash, "4a447a13c5a32730d20bdf7feecb9ffe16649bc731914b574d80035a3927f860");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
