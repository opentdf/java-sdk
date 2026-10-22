package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * The TDFWriter class provides functionalities for creating a TDF (Trusted Data Format) archive.
 * This includes appending a manifest file and appending payload data to the archive.
 */
public class TDFWriter {
    public static final String TDF_PAYLOAD_FILE_NAME = "0.payload";

    /**
     * The manifest entry name this SDK writes. The {@code 0.} prefix is a holdover from an
     * early design that anticipated several payload/manifest pairs per archive and never
     * shipped; the spec names the entry {@link #TDF_MANIFEST_FILE_NAME_SPEC}. Changing what
     * the writer emits is a breaking file-format change and is left to a separate change.
     * See <a href="https://github.com/opentdf/platform/issues/3513">platform#3513</a>.
     */
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";

    /**
     * The manifest entry name given by the OpenTDF spec:
     * <a href="https://opentdf.io/spec#tdf-structure">opentdf.io/spec</a>. Read-side only --
     * {@link TDFReader} accepts it so archives from spec-conformant implementations can be
     * read, and the writer does not yet emit it.
     */
    public static final String TDF_MANIFEST_FILE_NAME_SPEC = "manifest.json";

    private final ZipWriter archiveWriter;

    public TDFWriter(OutputStream destination) {
        this.archiveWriter = new ZipWriter(destination);
    }

    /**
     * Test seam. See {@link ZipWriter#ZipWriter(OutputStream, long)}.
     */
    TDFWriter(OutputStream destination, long maxNonZip64Value) {
        this.archiveWriter = new ZipWriter(destination, maxNonZip64Value);
    }

    /**
     * @deprecated use {@link #manifest()}. A manifest with tens of millions of segments
     *             exceeds the maximum size of a Java {@link String}, so this cannot
     *             express every manifest the SDK writes. It produces the same zip entry.
     */
    @SuppressWarnings("java:S1133") // Retained for source and binary compatibility.
    @Deprecated(since = "0.20.0", forRemoval = false)
    public void appendManifest(String manifest) throws IOException {
        try (OutputStream output = manifest()) {
            output.write(manifest.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Opens the manifest entry for writing. The returned stream must be closed before
     * {@link #finish()} is called, otherwise the entry never makes it into the central directory.
     */
    public OutputStream manifest() throws IOException {
        return this.archiveWriter.stream(TDF_MANIFEST_FILE_NAME);
    }

    public OutputStream payload() throws IOException {
        return this.archiveWriter.stream(TDF_PAYLOAD_FILE_NAME);

    }

    public long finish() throws IOException {
        return this.archiveWriter.finish();
    }
}
