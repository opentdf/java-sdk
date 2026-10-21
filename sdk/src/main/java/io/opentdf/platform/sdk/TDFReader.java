package io.opentdf.platform.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;

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
    private final ZipReader.Entry payloadEntry;
    /**
     * Opened by the first payload read rather than here, so reading only the manifest never
     * allocates an inflater for a deflated payload. Released by {@link #closePayload()}.
     */
    private InputStream payload;
    private boolean payloadReleased = false;

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
        payloadEntry = entries.get(TDF_PAYLOAD_FILE_NAME);
        // check the payload now, so one that can't be read (an unsupported compression method,
        // or a deflated size over its budget) is refused before any key is requested -- but
        // without opening it, since a caller may only want the manifest
        payloadEntry.checkReadable();
    }

    String manifest() {
        var out = new ByteArrayOutputStream();
        // closing releases the inflater when the manifest entry is deflated
        try (var manifestData = manifestEntry.getData()) {
            manifestData.transferTo(out);
        } catch (IOException e) {
            throw new SDKException("error retrieving manifest from zip file", e);
        }

        return out.toString(StandardCharsets.UTF_8);
    }

    /**
     * Reads the next payload bytes into {@code buf}, opening the payload on the first call. A
     * failed read releases the payload; once it has been released this reads nothing.
     */
    int readPayloadBytes(byte[] buf) {
        if (payloadReleased) {
            return 0;
        }
        int totalRead = 0;
        int nread;
        boolean succeeded = false;
        try {
            if (payload == null) {
                payload = payloadEntry.getData();
            }
            while (totalRead < buf.length && (nread = payload.read(buf, totalRead, buf.length - totalRead)) >= 0) {
                totalRead += nread;
            }
            succeeded = true;
        } catch (IOException e) {
            throw new SDKException("error reading from payload in TDF", e);
        } finally {
            if (!succeeded) {
                closePayload();
            }
        }
        return totalRead;
    }

    /**
     * Called once every segment has been read. A deflated payload must end exactly there: a
     * further read has to find the end of the entry, which for a deflated entry also confirms
     * the deflate stream ends at its declared size. A stored payload is not checked, as before.
     * Releases the payload either way.
     *
     * @throws InvalidZipException if a deflated payload holds data past its last segment
     */
    void finishPayload() {
        try {
            if (payloadEntry.getCompressionMethod() == ZipEntry.DEFLATED && !payloadReleased) {
                if (payload == null) {
                    payload = payloadEntry.getData();
                }
                if (payload.read() != -1) {
                    throw new InvalidZipException("deflated entry [" + payloadEntry.getName()
                            + "] holds data past the end of the TDF's last segment");
                }
            }
        } catch (IOException e) {
            throw new SDKException("error reading from payload in TDF", e);
        } finally {
            closePayload();
        }
    }

    /**
     * Releases the payload stream, and with it a deflated payload's inflater. Idempotent; after
     * it, payload reads return nothing.
     */
    void closePayload() {
        payloadReleased = true;
        if (payload == null) {
            return;
        }
        try {
            payload.close();
        } catch (IOException e) {
            throw new SDKException("error closing payload in TDF", e);
        } finally {
            payload = null;
        }
    }

    PolicyObject readPolicyObject() {
        String manifestJson = manifest();
        Manifest manifest = Manifest.readManifest(manifestJson);
        return Manifest.decodePolicyObject(manifest);
    }
}
