package io.opentdf.platform.sdk;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME;
import static io.opentdf.platform.sdk.TDFWriter.TDF_PAYLOAD_FILE_NAME;

/**
 * TDFReader is responsible for reading and processing Trusted Data Format (TDF) files.
 * The class initializes with a TDF file channel, extracts the manifest and payload entries,
 * and provides methods to retrieve the manifest content, read payload bytes, and read policy objects.
 */
public class TDFReader {

    private static final int MANIFEST_BUFFER_SIZE = 1 << 16;

    private final ZipReader.Entry manifestEntry;
    private final InputStream payload;

    public TDFReader(SeekableByteChannel tdf) throws SDKException, IOException {
        Map<String, ZipReader.Entry> entries = new ZipReader(tdf).getEntries()
                .stream()
                .collect(Collectors.toMap(ZipReader.Entry::getName, e -> e));

        if (!entries.containsKey(TDF_MANIFEST_FILE_NAME)) {
            throw new IllegalArgumentException("tdf doesn't contain a manifest");
        }
        if (!entries.containsKey(TDF_PAYLOAD_FILE_NAME)) {
            throw new IllegalArgumentException("tdf doesn't contain a payload");
        }

        manifestEntry = entries.get(TDF_MANIFEST_FILE_NAME);
        payload = entries.get(TDF_PAYLOAD_FILE_NAME).getData();
    }

    /**
     * The manifest entry as a character stream; the caller must close it. Returned
     * as a stream rather than a String because a manifest with tens of millions of
     * segments exceeds the maximum size of a Java String.
     */
    Reader manifest() {
        try {
            return new BufferedReader(
                    new InputStreamReader(manifestEntry.getData(), StandardCharsets.UTF_8), MANIFEST_BUFFER_SIZE);
        } catch (IOException e) {
            throw new SDKException("error retrieving manifest from zip file", e);
        }
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

    PolicyObject readPolicyObject() {
        try (Reader manifestJson = manifest()) {
            return Manifest.decodePolicyObject(Manifest.readManifest(manifestJson));
        } catch (IOException e) {
            throw new SDKException("error reading manifest from zip file", e);
        }
    }
}
