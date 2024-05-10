package io.opentdf.platform.sdk;

import java.io.*;

public class TDFWriter {
    private ZipWriter archiveWriter;
    public static final String TDF_PAYLOAD_FILE_NAME = "0.payload";
    public static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";

    public TDFWriter(OutputStream outStream) throws FileNotFoundException {
        this.archiveWriter = new ZipWriter(outStream);
    }

    public void setPayloadSize(long payloadSize) throws IOException {
        if (payloadSize >= 4L * 1024 * 1024 * 1024) { // if file size is greater than 4GB)
            this.archiveWriter.enableZip64();
        }

        this.archiveWriter.addHeader(TDF_PAYLOAD_FILE_NAME, payloadSize);
    }

    public void appendManifest(String manifest) throws IOException {
        this.archiveWriter.addHeader(TDF_MANIFEST_FILE_NAME, (long) manifest.length());
        this.archiveWriter.addData(manifest.getBytes());
    }

    public void appendPayload(byte[] data) throws IOException {
        this.archiveWriter.addData(data);
    }

    public void finish() throws IOException {
        this.archiveWriter.finish();
    }
}