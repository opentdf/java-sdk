package io.opentdf.platform.sdk;

import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.Reader;

/**
 * Parsing of assertion wire objects, as Section 3 of the ZTDF assertions specification defines
 * it.
 */
final class AssertionJson {

    private AssertionJson() {
    }

    /**
     * Applies only the manifest-level checks of Section 3 to a whole manifest, without building
     * the typed manifest. Malformed JSON is reported as {@code invalid-json} here; the manifest
     * reader proper reports it as a malformed TDF.
     *
     * @throws SDK.AssertionFailureException on the first failure in document order
     */
    static void checkManifest(Reader manifestJson) {
        try (StrictJsonReader reader = new StrictJsonReader(manifestJson, StrictJsonReader.Mode.MANIFEST)) {
            reader.skipValue();
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw invalidJson("unexpected content after the manifest");
            }
        } catch (IOException | IllegalStateException | NumberFormatException e) {
            throw invalidJson("the manifest is not valid JSON");
        }
    }

    private static SDK.AssertionFailureException invalidJson(String detail) {
        return new SDK.AssertionFailureException(null, AssertionFailureReason.INVALID_JSON, detail);
    }
}
