package io.opentdf.platform.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME;
import static io.opentdf.platform.sdk.TDFWriter.TDF_PAYLOAD_FILE_NAME;

public class TDFReader {

    private static final int MAX_MANIFEST_SIZE_MB = 10;
    private static final int BYTES_IN_MB = 1024 * 1024;
    private static final int MAX_MANIFEST_SIZE_BYTES = MAX_MANIFEST_SIZE_MB * BYTES_IN_MB;
    private final ZipReader.Entry manifest;
    private final InputStream payload;

    public TDFReader(SeekableByteChannel tdf) throws IOException {
        var entries = new ZipReader(tdf).getEntries()
                .stream()
                .collect(Collectors.toMap(ZipReader.Entry::getName, e -> e));

        if (!entries.containsKey(TDF_MANIFEST_FILE_NAME)) {
            throw new IllegalArgumentException("tdf doesn't contain a manifest");
        }
        if (!entries.containsKey(TDF_PAYLOAD_FILE_NAME)) {
            throw new IllegalArgumentException("tdf doesn't contain a payload");
        }

        manifest = entries.get(TDF_MANIFEST_FILE_NAME);
        if (manifest.getFileSize() > MAX_MANIFEST_SIZE_BYTES) {
            throw new SDKException("manifest file too large: " + (manifest.getFileSize() / (double) BYTES_IN_MB) + " MB");
        }

        payload = entries.get(TDF_PAYLOAD_FILE_NAME).getData();
    }

    public String manifest() {
        var out = new ByteArrayOutputStream();
        try {
            manifest.getData().transferTo(out);
        } catch (IOException e) {
            throw new SDKException("error retrieving manifest from zip file", e);
        }

        return out.toString(StandardCharsets.UTF_8);
    }

    int readPayloadBytes(byte[] buf) {
        int totalRead = 0;
        int nread;
        try {
            while (totalRead < buf.length && (nread = payload.read(buf, totalRead, buf.length - totalRead)) >= 0) {
                totalRead += nread;
            }
        } catch (IOException e) {
            throw new SDKException("error reading from payload in TDF", e);
        }
        return totalRead;
    }
}
