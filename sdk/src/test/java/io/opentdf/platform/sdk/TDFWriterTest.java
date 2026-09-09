package io.opentdf.platform.sdk;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TDFWriterTest {
    @Test
    void simpleTDFCreate() throws IOException {

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
        String payload = "Hello, world!";
        var tdfFile = File.createTempFile("sample", ".tdf");
        tdfFile.deleteOnExit();
        try (var fileOutStream = new FileOutputStream(tdfFile)) {
            TDFWriter writer = new TDFWriter(fileOutStream);
            try (var p = writer.payload()) {
                new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)).transferTo(p);
            }
            try (var m = writer.manifest()) {
                m.write(kManifestJsonFromTDF.getBytes(StandardCharsets.UTF_8));
            }
            writer.finish();
        }

        // our own reader
        try (var channel = FileChannel.open(tdfFile.toPath(), StandardOpenOption.READ)) {
            var entries = new ZipReader(channel).getEntries().stream()
                    .collect(Collectors.toMap(ZipReader.Entry::getName, e -> e));
            assertEquals(kManifestJsonFromTDF,
                    new String(entries.get(TDFWriter.TDF_MANIFEST_FILE_NAME).getData().readAllBytes(),
                            StandardCharsets.UTF_8));
            assertEquals(payload,
                    new String(entries.get(TDFWriter.TDF_PAYLOAD_FILE_NAME).getData().readAllBytes(),
                            StandardCharsets.UTF_8));
        }

        // an independent central-directory based reader, as a stand-in for the other SDKs
        try (var zipFile = new ZipFile(tdfFile)) {
            var manifestEntry = zipFile.getEntry(TDFWriter.TDF_MANIFEST_FILE_NAME);
            assertNotNull(manifestEntry);
            try (var in = zipFile.getInputStream(manifestEntry)) {
                assertEquals(kManifestJsonFromTDF, new String(in.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * The manifest is appended after the payload, so in a large TDF its local header offset
     * doesn't fit in a 32-bit central directory field. Uses the lowered zip64 threshold to run
     * that path against a small file.
     */
    @Test
    void readsBackAManifestWrittenPastTheZip64Boundary() throws IOException {
        var manifest = "{\"payload\":{\"url\":\"0.payload\"}}";
        var payload = "a payload long enough to push the manifest past the threshold";

        var out = new ByteArrayOutputStream();
        var writer = new TDFWriter(out, 8);
        try (var p = writer.payload()) {
            new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)).transferTo(p);
        }
        try (var m = writer.manifest()) {
            m.write(manifest.getBytes(StandardCharsets.UTF_8));
        }
        writer.finish();

        try (var chan = new SeekableInMemoryByteChannel(out.toByteArray())) {
            var reader = new TDFReader(chan);
            var readBack = new StringWriter();
            try (var m = reader.manifest()) {
                m.transferTo(readBack);
            }
            assertEquals(manifest, readBack.toString());

            var payloadBytes = new byte[payload.length()];
            assertEquals(payload.length(), reader.readPayloadBytes(payloadBytes));
            assertEquals(payload, new String(payloadBytes, StandardCharsets.UTF_8));
        }
    }
}
