package io.opentdf.platform.sdk;

import com.google.gson.JsonParseException;

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
import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME_SPEC;
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

    /**
     * Opens a TDF read from untrusted bytes, reporting a container that is not a well formed
     * TDF as a {@link SDK.MalformedTDFException} rather than as whichever unchecked exception
     * the zip reader or this class's own checks happened to raise.
     */
    static TDFReader open(SeekableByteChannel tdf) throws IOException {
        try {
            return new TDFReader(tdf);
        } catch (InvalidZipException | IllegalArgumentException e) {
            throw malformed("tdf is not a valid zip container", e);
        }
    }

    /**
     * Reads and validates the manifest. Malformed JSON, and JSON that does not have the shape of
     * a manifest, is reported as a {@link SDK.MalformedTDFException}.
     */
    Manifest readManifest() {
        try (Reader manifestJson = manifest()) {
            return Manifest.readManifest(manifestJson);
        } catch (InvalidZipException e) {
            // the manifest entry runs past the end of the archive
            throw malformed("error retrieving manifest from zip file", e);
        } catch (JsonParseException | IllegalArgumentException | IllegalStateException
                 | UnsupportedOperationException e) {
            // Gson reports a JSON value of the wrong type through IllegalStateException and
            // UnsupportedOperationException (the JsonElement.getAsX accessors), and
            // Manifest.readManifest reports missing required fields as IllegalArgumentException.
            // Every one of these here means the manifest itself is malformed.
            throw malformed("tdf manifest is invalid", e);
        } catch (IOException e) {
            throw new SDKException("error reading manifest from zip file", e);
        }
    }

    private static SDK.MalformedTDFException malformed(String what, RuntimeException e) {
        return new SDK.MalformedTDFException(what + ": " + e.getMessage(), e);
    }

    /**
     * The manifest entry as a character stream; the caller must close it. Returned
     * as a stream rather than a String because a manifest with tens of millions of
     * segments exceeds the maximum size of a Java String.
     */
    Reader manifest() {
        // deliberately no fixed size cap: very large payloads (DSPX-4502) have manifests well
        // over a gigabyte. a hostile declared size cannot make this allocate more than the
        // archive holds, because the stream stops at the end of the archive and reports the
        // entry as truncated, and ZipReader rejects entries whose stored bytes do not fit
        try {
            return new BufferedReader(
                    new InputStreamReader(manifestEntry.getData(), StandardCharsets.UTF_8), MANIFEST_BUFFER_SIZE);
        } catch (InvalidZipException e) {
            throw malformed("error retrieving manifest from zip file", e);
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
        } catch (InvalidZipException e) {
            // the payload entry runs past the end of the archive
            throw malformed("error reading from payload in TDF", e);
        } catch (IOException e) {
            throw new SDKException("error reading from payload in TDF", e);
        }
        return totalRead;
    }

    PolicyObject readPolicyObject() {
        Manifest manifest = readManifest();
        return Manifest.decodePolicyObject(manifest);
    }
}
