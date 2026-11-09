package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonToken;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;

/**
 * Parsing and hashing of assertion wire objects, as Sections 3 and 4 of the ZTDF assertions
 * specification define them.
 */
final class AssertionJson {

    /** Gson's own JSON tree adapter; it reads through whatever reader it is handed. */
    static final TypeAdapter<JsonElement> JSON_ELEMENT = new Gson().getAdapter(JsonElement.class);

    private static final String BINDING = "binding";

    private AssertionJson() {
    }

    /**
     * Parses the raw JSON text of one assertion wire object under Section 3: no duplicate member
     * names anywhere in it, no case variants of the modelled names at the assertion, statement
     * and binding levels, and I-JSON content throughout.
     *
     * @throws SDK.AssertionFailureException if the text is not such an object
     */
    static JsonObject parseAssertion(String wireJson) {
        Objects.requireNonNull(wireJson, "wireJson");
        try (StrictJsonReader reader = new StrictJsonReader(new StringReader(wireJson), StrictJsonReader.Mode.ASSERTION)) {
            if (reader.peek() != JsonToken.BEGIN_OBJECT) {
                throw invalidJson("an assertion must be a JSON object");
            }
            JsonObject assertion = JSON_ELEMENT.read(reader).getAsJsonObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw invalidJson("unexpected content after the assertion object");
            }
            return assertion;
        } catch (IOException | IllegalStateException | NumberFormatException e) {
            throw invalidJson("the assertion is not valid JSON");
        }
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

    /**
     * Parses any JSON value, rejecting duplicate member names but applying none of the
     * assertion-specific rules. Used for JWS headers and claims.
     *
     * @throws IOException or a {@link SDK.AssertionFailureException} if the text is not strict JSON
     */
    static JsonElement parseStrict(String json) throws IOException {
        try (StrictJsonReader reader = new StrictJsonReader(new StringReader(json), StrictJsonReader.Mode.GENERIC)) {
            JsonElement element = JSON_ELEMENT.read(reader);
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw new IOException("unexpected content after the JSON value");
            }
            return element;
        } catch (IllegalStateException | NumberFormatException e) {
            throw new IOException("not valid JSON", e);
        }
    }

    /**
     * {@code assertionHash} as Section 4 defines it: the lowercase hex SHA-256 of the JCS (RFC
     * 8785) form of the assertion with only its top-level {@code binding} member removed.
     * Everything else, including members this SDK does not model and the JSON type of
     * {@code statement.value}, is hashed exactly as given.
     *
     * @param assertion an assertion that has passed {@link #parseAssertion} or the manifest reader
     */
    static String hash(JsonObject assertion) {
        JsonObject withoutBinding = new JsonObject();
        for (Map.Entry<String, JsonElement> member : assertion.entrySet()) {
            if (!BINDING.equals(member.getKey())) {
                withoutBinding.add(member.getKey(), member.getValue());
            }
        }
        byte[] canonical;
        try {
            // JsonElement.toString writes JSON nulls and keeps each number's original text, which
            // the canonicalizer then reads as an IEEE 754 double, as RFC 8785 requires
            canonical = new JsonCanonicalizer(withoutBinding.toString()).getEncodedUTF8();
        } catch (IOException e) {
            throw invalidJson("the assertion cannot be canonicalized: " + e.getMessage());
        }
        return Hex.encodeHexString(sha256(canonical));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error creating SHA-256 message digest", e);
        }
    }

    private static SDK.AssertionFailureException invalidJson(String detail) {
        return new SDK.AssertionFailureException(null, AssertionFailureReason.INVALID_JSON, detail);
    }
}
