package io.opentdf.platform.sdk;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The OpenTDF spec names the manifest entry {@code manifest.json}; this SDK writes
 * {@code 0.manifest.json}, so the reader accepts either.
 * See <a href="https://github.com/opentdf/platform/issues/3513">platform#3513</a>.
 */
public class TDFReaderTest {

    /**
     * Manifest-shaped, but deliberately not schema-complete: {@link TDFReader#manifest()}
     * hands back the entry's bytes without parsing them, and these tests are about which
     * entry it picks. {@link Manifest#readManifest} would reject this literal -- it has no
     * integrityInformation -- so anything that parses belongs in a test that builds a real
     * manifest instead.
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

    /**
     * Builds a zip holding exactly the given name/content pairs, in the order given. Writes
     * each pair straight through, so a name may repeat -- that is a legal zip and one of the
     * inputs under test.
     */
    private static SeekableInMemoryByteChannel archiveOf(String... namesAndContents) throws IOException {
        if (namesAndContents.length % 2 != 0) {
            throw new IllegalArgumentException("expected name/content pairs");
        }
        var out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out);
        for (int i = 0; i < namesAndContents.length; i += 2) {
            writer.data(namesAndContents[i], namesAndContents[i + 1].getBytes(StandardCharsets.UTF_8));
        }
        writer.finish();
        return new SeekableInMemoryByteChannel(out.toByteArray());
    }

    @Test
    void readsManifestUnderTheSpecName() throws IOException {
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "manifest.json", MANIFEST)) {
            assertThat(new TDFReader(tdf).manifest()).isEqualTo(MANIFEST);
        }
    }

    @Test
    void readsManifestUnderTheOffspecName() throws IOException {
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "0.manifest.json", MANIFEST)) {
            assertThat(new TDFReader(tdf).manifest()).isEqualTo(MANIFEST);
        }
    }

    /**
     * The two entries hold different manifests, so this cannot pass by reading whichever
     * one the reader happened to pick.
     */
    @Test
    void prefersTheSpecNameWhenAnArchiveCarriesBoth() throws IOException {
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "0.manifest.json", OTHER_MANIFEST,
                "manifest.json", MANIFEST)) {
            assertThat(new TDFReader(tdf).manifest()).isEqualTo(MANIFEST);
        }
    }

    @Test
    void rejectsAnArchiveWithNoManifestUnderEitherName() throws IOException {
        try (var tdf = archiveOf(TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD)) {
            assertThatThrownBy(() -> new TDFReader(tdf))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tdf doesn't contain a manifest");
        }
    }

    /**
     * The match is exact and rooted. The spec requires the manifest to "reside within the
     * root of the OpenTDF Zip archive", so a nested or differently-cased entry is not it --
     * without this, a basename or case-insensitive match would look equally correct.
     */
    @Test
    void rejectsNearMissManifestEntryNames() throws IOException {
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "Manifest.json", MANIFEST,
                "sub/manifest.json", MANIFEST,
                "evil-manifest.json", MANIFEST)) {
            assertThatThrownBy(() -> new TDFReader(tdf))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("tdf doesn't contain a manifest");
        }
    }

    /**
     * A zip may list one name twice; readers disagree about which copy wins, so this one
     * refuses to choose. Distinct from an archive carrying both manifest names, which is
     * read: there, the spec settles the choice.
     */
    @Test
    void rejectsAnArchiveThatListsOneNameTwice() throws IOException {
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "manifest.json", MANIFEST)) {
            assertThatThrownBy(() -> new TDFReader(tdf))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("more than one entry named " + TDFWriter.TDF_PAYLOAD_FILE_NAME);
        }
    }

    @Test
    void rejectsAnArchiveThatListsTheManifestNameTwice() throws IOException {
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "manifest.json", MANIFEST,
                "manifest.json", OTHER_MANIFEST)) {
            assertThatThrownBy(() -> new TDFReader(tdf))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("more than one entry named manifest.json");
        }
    }

    /** The buffer is one byte longer than the payload, so a short read would show up. */
    @Test
    void readsThePayloadAlongsideASpecNamedManifest() throws IOException {
        var expected = PAYLOAD.getBytes(StandardCharsets.UTF_8);
        try (var tdf = archiveOf(
                TDFWriter.TDF_PAYLOAD_FILE_NAME, PAYLOAD,
                "manifest.json", MANIFEST)) {
            var reader = new TDFReader(tdf);
            var buf = new byte[expected.length + 1];

            assertThat(reader.readPayloadBytes(buf)).isEqualTo(expected.length);
            assertThat(buf).startsWith(expected);
        }
    }
}
