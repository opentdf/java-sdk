package io.opentdf.platform.sdk;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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

    String manifest() {
        var out = new ByteArrayOutputStream();
        try {
            manifestEntry.getData().transferTo(out);
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

    PolicyObject readPolicyObject() {
        String manifestJson = manifest();
        Manifest manifest = Manifest.readManifest(manifestJson);
        return Manifest.decodePolicyObject(manifest);
    }
}
