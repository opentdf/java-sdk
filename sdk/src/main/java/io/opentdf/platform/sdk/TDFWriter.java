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
     * The legacy manifest entry name this SDK writes by default. The {@code 0.} prefix is a
     * holdover from an early design that anticipated several payload/manifest pairs per
     * archive and never shipped. The unprefixed name {@link #TDF_MANIFEST_FILE_NAME_SPEC}
     * is opt-in. See <a href="https://github.com/opentdf/platform/issues/3513">platform#3513</a>.
     */
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";

    /**
     * The manifest entry name given by the OpenTDF spec:
     * <a href="https://opentdf.io/spec#tdf-structure">opentdf.io/spec</a>.
     * {@link TDFReader} accepts it, and the writer emits it when
     * {@link Config#withUnprefixedManifestName()} is set.
     */
    public static final String TDF_MANIFEST_FILE_NAME_SPEC = "manifest.json";

    private final ZipWriter archiveWriter;
    private final String manifestFileName;

    public TDFWriter(OutputStream destination) {
        this(destination, TDF_MANIFEST_FILE_NAME);
    }

    TDFWriter(OutputStream destination, String manifestFileName) {
        this.archiveWriter = new ZipWriter(destination);
        this.manifestFileName = manifestFileName;
    }

    /**
     * Test seam. See {@link ZipWriter#ZipWriter(OutputStream, long)}.
     */
    TDFWriter(OutputStream destination, long maxNonZip64Value) {
        this.archiveWriter = new ZipWriter(destination, maxNonZip64Value);
        this.manifestFileName = TDF_MANIFEST_FILE_NAME;
    }

    public void appendManifest(String manifest) throws IOException {
        this.archiveWriter.data(manifestFileName, manifest.getBytes(StandardCharsets.UTF_8));
    }

    public OutputStream payload() throws IOException {
        return this.archiveWriter.stream(TDF_PAYLOAD_FILE_NAME);

    }

    public long finish() throws IOException {
        return this.archiveWriter.finish();
    }
}