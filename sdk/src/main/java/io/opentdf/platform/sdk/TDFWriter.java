package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class TDFWriter {
    public static final String TDF_PAYLOAD_FILE_NAME = "0.payload";
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";
    private final ZipWriter archiveWriter;

    public TDFWriter(OutputStream destination) {
        this.archiveWriter = new ZipWriter(destination);
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