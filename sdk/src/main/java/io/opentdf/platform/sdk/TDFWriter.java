package io.opentdf.platform.sdk;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class TDFWriter {
    private ZipWriter archiveWriter;
    private final OutputStream destination;
    public static final String TDF_PAYLOAD_FILE_NAME = "0.payload";
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";

    public TDFWriter(OutputStream destination) {
        this.destination = destination;
        this.archiveWriter = new ZipWriter();
    }

    public void appendManifest(String manifest) {
        this.archiveWriter = this.archiveWriter.file(TDF_MANIFEST_FILE_NAME, manifest.getBytes(StandardCharsets.UTF_8));
    }

    public void appendPayload(byte[] data) {
        this.archiveWriter = this.archiveWriter.file(TDF_PAYLOAD_FILE_NAME, data);
    }

    public long finish() throws IOException {
        return this.archiveWriter.build(this.destination);
    }
}