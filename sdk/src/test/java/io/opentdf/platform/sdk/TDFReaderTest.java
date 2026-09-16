package io.opentdf.platform.sdk;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The OpenTDF spec names the manifest entry {@code manifest.json}; this SDK writes
 * {@code 0.manifest.json}, so the reader accepts either.
 * See <a href="https://github.com/opentdf/platform/issues/3513">platform#3513</a>.
 */
public class TDFReaderTest {

    /**
     * Carries the fields the TDF manifest schema requires, so the fixtures below are
     * manifests rather than arbitrary JSON. {@link TDFReader#manifest()} hands back the
     * bytes without parsing them, so the literal is spelled out here.
     */
    private static String manifestJson(String mimeType) {
        return "{\"payload\":{\"type\":\"reference\",\"url\":\"" + TDFWriter.TDF_PAYLOAD_FILE_NAME
                + "\",\"protocol\":\"zip\",\"isEncrypted\":true,\"mimeType\":\"" + mimeType
                + "\"},\"encryptionInformation\":{\"type\":\"split\"}}";
    }

    /**
     * What nearly every fixture here stores. These tests exercise the entry name, not
     * manifest contents, so the same manifest serves whichever name it is filed under.
     */
    private static final String MANIFEST = manifestJson("application/octet-stream");

    /**
     * Exists only for the test that must tell the two entries apart -- with identical
     * content, it could not say which one the reader returned.
     */
    private static final String OTHER_MANIFEST = manifestJson("text/plain");

    private static final String PAYLOAD = "payload bytes";

    /** Builds a zip holding exactly the given entries, in iteration order. */
    private static SeekableInMemoryByteChannel archiveOf(Map<String, String> entries) throws IOException {
        var out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out);
        for (var entry : entries.entrySet()) {
            writer.data(entry.getKey(), entry.getValue().getBytes(StandardCharsets.UTF_8));
        }
        writer.finish();
        return new SeekableInMemoryByteChannel(out.toByteArray());
    }

    private static Map<String, String> entries(String... namesAndContents) {
        var entries = new LinkedHashMap<String, String>();
        for (int i = 0; i < namesAndContents.length; i += 2) {
            entries.put(namesAndContents[i], namesAndContents[i + 1]);
        }
        return entries;
    }

    @Test
    void readsManifestUnderTheSpecName() throws IOException {
        try (var tdf = archiveOf(entries(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "manifest.json", MANIFEST))) {
            assertThat(new TDFReader(tdf).manifest()).isEqualTo(MANIFEST);
        }
    }

    @Test
    void readsManifestUnderTheOffspecName() throws IOException {
        try (var tdf = archiveOf(entries(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "0.manifest.json", MANIFEST))) {
            assertThat(new TDFReader(tdf).manifest()).isEqualTo(MANIFEST);
        }
    }

    /**
     * The two entries hold different manifests, so this cannot pass by reading whichever
     * one the reader happened to pick.
     */
    @Test
    void prefersTheSpecNameWhenAnArchiveCarriesBoth() throws IOException {
        try (var tdf = archiveOf(entries(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "0.manifest.json", OTHER_MANIFEST,
                "manifest.json", MANIFEST))) {
            assertThat(new TDFReader(tdf).manifest()).isEqualTo(MANIFEST);
        }
    }

    @Test
    void rejectsAnArchiveWithNoManifestUnderEitherName() throws IOException {
        try (var tdf = archiveOf(entries(TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD))) {
            assertThatThrownBy(() -> new TDFReader(tdf))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tdf doesn't contain a manifest");
        }
    }

    @Test
    void readsThePayloadAlongsideASpecNamedManifest() throws IOException {
        try (var tdf = archiveOf(entries(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "manifest.json", MANIFEST))) {
            var reader = new TDFReader(tdf);
            var buf = new byte[PAYLOAD.length()];

            assertThat(reader.readPayloadBytes(buf)).isEqualTo(PAYLOAD.length());
            assertThat(new String(buf, StandardCharsets.UTF_8)).isEqualTo(PAYLOAD);
        }
    }
}
