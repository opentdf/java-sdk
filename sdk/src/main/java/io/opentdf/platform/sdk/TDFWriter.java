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
     * The manifest entry name given by the OpenTDF spec:
     * <a href="https://opentdf.io/spec#tdf-structure">opentdf.io/spec</a>.
     */
    public static final String TDF_MANIFEST_FILE_NAME = "manifest.json";

    /**
     * The manifest entry name this SDK wrote before the spec alignment. The {@code 0.}
     * prefix is a holdover from an early design that anticipated several payload/manifest
     * pairs per archive and never shipped. Readers still accept it; the writer no longer
     * emits it.
     * See <a href="https://github.com/opentdf/platform/issues/3513">platform#3513</a>.
     */
    public static final String TDF_MANIFEST_FILE_NAME_OFFSPEC = "0.manifest.json";
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

    public void appendManifest(String manifest) throws IOException {
        this.archiveWriter.data(TDF_MANIFEST_FILE_NAME, manifest.getBytes(StandardCharsets.UTF_8));
    }

    public OutputStream payload() throws IOException {
        return this.archiveWriter.stream(TDF_PAYLOAD_FILE_NAME);

    }

    public long finish() throws IOException {
        return this.archiveWriter.finish();
    }
}