package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.Strictness;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.MalformedJsonException;
import dev.harrel.jsonschema.Error;
import dev.harrel.jsonschema.Validator;
import dev.harrel.jsonschema.ValidatorFactory;
import dev.harrel.jsonschema.providers.GsonNode;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The check behind {@link SDK#isValidTdf} and {@link SDK#validateTdf}. It asks the question that
 * the Go SDK's {@code IsValidTdf} and the web SDK's {@code isValidTdf} ask: can the archive be
 * opened, and does its manifest satisfy the lax manifest schema?
 * <p>
 * {@code manifest-lax.schema.json} is vendored byte for byte from the OpenTDF Go SDK v0.35.0,
 * <a href="https://github.com/opentdf/platform/blob/sdk/v0.35.0/sdk/schema/manifest-lax.schema.json">
 * sdk/schema/manifest-lax.schema.json</a> (SHA-256
 * {@code 5e361720f005b23211a37d9e89c2c7ef51bc1b7df3353b82c2a568c3ed33f87d}). To refresh it, copy
 * the file from a newer {@code sdk/} tag of opentdf/platform without editing it, and update the
 * version and hash here and in {@code TDFValidatorTest}.
 */
final class TDFValidator {

    static final String LAX_SCHEMA_RESOURCE = "manifest-lax.schema.json";

    /**
     * The deepest nesting a manifest may have. This is the limit in Go's {@code encoding/json}, so
     * Go and Java reject the same deeply nested manifests.
     */
    static final int MAX_NESTING_DEPTH = 10_000;

    private static final char BYTE_ORDER_MARK = '\uFEFF';

    /** Where Gson's syntax error messages say the problem is. */
    private static final Pattern GSON_LOCATION = Pattern.compile("at line \\d+ column \\d+");

    private static final TypeAdapter<JsonElement> JSON_TREE = new Gson().getAdapter(JsonElement.class);

    // registerSchema is the only call that changes a Validator, and it happens once, here.
    // validate() gives each call its own evaluation state, so concurrent calls are safe
    private static final Validator VALIDATOR = new ValidatorFactory()
            .withJsonNodeFactory(new GsonNode.Factory())
            .createValidator();
    private static final URI LAX_SCHEMA = VALIDATOR.registerSchema(readLaxSchema());

    private TDFValidator() {
    }

    /**
     * Returns normally if the channel holds a valid TDF.
     *
     * @throws SDK.MalformedTDFException if it doesn't, with the first problem found as its message
     * @throws IOException if the channel can't be read
     */
    static void validate(SeekableByteChannel channel) throws IOException {
        // the same container checks as SDK.readManifest and loadTDF, so a TDF this calls valid is
        // one their reader can open: the manifest is chosen the same way, and an archive listing
        // a name twice, or without a payload, is refused here as it is there
        var tdf = TDFReader.open(channel);
        checkAgainstLaxSchema(readManifest(tdf));
    }

    private static JsonElement readManifest(TDFReader tdf) throws IOException {
        try (var manifest = new PushbackReader(openManifest(tdf), 1)) {
            // Gson skips a leading byte order mark without complaint, so look for one first. Go's
            // JSON reader treats one as an error, and RFC 8259 forbids sending one
            int first = manifest.read();
            if (first == BYTE_ORDER_MARK) {
                throw new SDK.MalformedTDFException("manifest starts with a byte order mark");
            }
            if (first != -1) {
                manifest.unread(first);
            }
            return parseStrictly(manifest);
        } catch (InvalidZipException e) {
            // the entry stream found the data malformed part way through: it ran past the end of
            // the archive, or, for a reader that inflates compressed entries, it is corrupt
            throw malformed("manifest entry can't be read", e);
        }
    }

    /** {@link TDFReader#manifest()} reports an I/O failure as an SDKException; undo that. */
    private static Reader openManifest(TDFReader tdf) throws IOException {
        try {
            return tdf.manifest();
        } catch (SDK.MalformedTDFException e) {
            throw e;
        } catch (SDKException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw e;
        }
    }

    /**
     * Parses exactly one RFC 8259 JSON value. Gson's strict mode turns away what its lenient
     * default lets through (comments, single quotes, unquoted names, trailing commas, NaN, and
     * so on), and a second value or other data after the first is refused rather than ignored.
     */
    private static JsonElement parseStrictly(Reader manifest) throws IOException {
        var json = new JsonReader(manifest);
        json.setStrictness(Strictness.STRICT);
        json.setNestingLimit(MAX_NESTING_DEPTH);
        JsonElement tree;
        try {
            // the type adapter rather than JsonParser.parseReader, which would turn an
            // OutOfMemoryError into a JsonParseException, and so into a false negative
            tree = JSON_TREE.read(json);
        } catch (MalformedJsonException | EOFException e) {
            // an EOFException is the JSON ending early; the archive ending early is an
            // InvalidZipException, and any other IOException is a failure to read
            throw new SDK.MalformedTDFException("manifest is not valid JSON: " + jsonProblem(e), e);
        }
        try {
            // in strict mode, peek either finds the end or throws
            if (json.peek() != JsonToken.END_DOCUMENT) {
                throw new MalformedJsonException("expected the end of the manifest " + json);
            }
        } catch (MalformedJsonException e) {
            var where = GSON_LOCATION.matcher(String.valueOf(e.getMessage()));
            throw new SDK.MalformedTDFException("manifest has data after its JSON value"
                    + (where.find() ? ", starting " + where.group() : ""), e);
        }
        return tree;
    }

    /**
     * Gson's description of a syntax error, without the troubleshooting link it puts on a second
     * line, and without its advice to parse leniently, which does not belong in a reason a TDF
     * is invalid.
     */
    private static String jsonProblem(IOException e) {
        return String.valueOf(e.getMessage()).split("\\R", 2)[0]
                .replace("Use JsonReader.setStrictness(Strictness.LENIENT) to accept malformed JSON", "malformed JSON");
    }

    private static void checkAgainstLaxSchema(JsonElement manifest) {
        Validator.Result result;
        try {
            result = VALIDATOR.validate(LAX_SCHEMA, manifest);
        } catch (RuntimeException e) {
            // the manifest is already in memory, so nothing here reads from the channel: whatever
            // goes wrong is down to the manifest. Gson refuses to convert a number of more than
            // 10,000 digits, or one with an exponent that large, so a manifest holding one where
            // the schema looks lands here; Go also reports a validator failure as invalid
            throw malformed("manifest could not be checked against the lax manifest schema", e);
        }
        if (!result.isValid()) {
            throw new SDK.MalformedTDFException(describe(result.getErrors()));
        }
    }

    private static String describe(List<Error> errors) {
        var description = new StringBuilder("manifest does not match the lax manifest schema");
        if (!errors.isEmpty()) {
            var first = errors.get(0);
            String location = first.getInstanceLocation();
            description.append(" at ").append(location.isEmpty() ? "the top level" : location)
                    .append(": ").append(first.getError());
            if (errors.size() > 1) {
                description.append(" (and ").append(errors.size() - 1).append(" more)");
            }
        }
        return oneLine(description.toString());
    }

    private static SDK.MalformedTDFException malformed(String what, Exception e) {
        return new SDK.MalformedTDFException(oneLine(what + ": " + e.getMessage()), e);
    }

    /** A reason is printed as one line of output, so it should be one line. */
    private static String oneLine(String message) {
        return message.replaceAll("\\s*\\R\\s*", " ");
    }

    private static String readLaxSchema() {
        try (InputStream schema = Objects.requireNonNull(TDFValidator.class.getResourceAsStream(LAX_SCHEMA_RESOURCE),
                LAX_SCHEMA_RESOURCE + " is missing from the classpath")) {
            return new String(schema.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("reading " + LAX_SCHEMA_RESOURCE, e);
        }
    }
}
