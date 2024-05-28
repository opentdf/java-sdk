package io.opentdf.platform.sdk;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class TDFWriter {
    private final OutputStream outStream;
    private ZipWriter archiveWriter;
    public static final String TDF_PAYLOAD_FILE_NAME = "0.payload";
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";

    public TDFWriter(OutputStream outStream) throws FileNotFoundException {
        this.archiveWriter = new ZipWriter();
        this.outStream = outStream;
    }

    public void appendManifest(String manifest) throws IOException {
        this.archiveWriter.file(TDF_MANIFEST_FILE_NAME, manifest.getBytes(StandardCharsets.UTF_8));
    }

    public void appendPayload(byte[] data) throws IOException {
        this.archiveWriter.file(TDF_PAYLOAD_FILE_NAME, data);
    }

    public long finish() throws IOException {
        return this.archiveWriter.build(outStream);
    }
}