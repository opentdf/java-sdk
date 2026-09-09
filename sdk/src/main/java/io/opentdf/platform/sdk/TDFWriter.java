package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;

/**
 * The TDFWriter class provides functionalities for creating a TDF (Trusted Data Format) archive.
 * This includes appending a manifest file and appending payload data to the archive.
 */
public class TDFWriter {
    public static final String TDF_PAYLOAD_FILE_NAME = "0.payload";
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";
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