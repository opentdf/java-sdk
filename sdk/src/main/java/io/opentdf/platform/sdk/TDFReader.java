package io.opentdf.platform.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME;
import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME_SPEC;
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
        // A zip may legally list the same name twice, and readers disagree about which copy
        // wins, so reject rather than pick one. Without a merge function this collector throws
        // IllegalStateException -- outside the constructor's declared error model, and outside
        // what callers screening untrusted input catch.
        Map<String, ZipReader.Entry> entries = new ZipReader(tdf).getEntries()
                .stream()
                .collect(Collectors.toMap(ZipReader.Entry::getName, e -> e, (first, second) -> {
                    throw new IllegalArgumentException("tdf contains more than one entry named " + first.getName());
                }));

        // An archive carrying both names is read, not rejected, and the spec name wins, so a
        // conformant entry is never passed over for a superseded one. Two entries under the
        // two names are distinct entries -- unlike the duplicate above, where one name is
        // listed twice and there is no principled way to choose.
        var manifest = entries.getOrDefault(TDF_MANIFEST_FILE_NAME_SPEC, entries.get(TDF_MANIFEST_FILE_NAME));
        if (manifest == null) {
            throw new IllegalArgumentException("tdf doesn't contain a manifest");
        }
        if (!entries.containsKey(TDF_PAYLOAD_FILE_NAME)) {
            throw new IllegalArgumentException("tdf doesn't contain a payload");
        }

        manifestEntry = manifest;
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
