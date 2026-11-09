package io.opentdf.platform.sdk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the DSPX-5520 shared assertion conformance vectors, which the Go, Java and JavaScript
 * SDKs all vendor byte for byte from opentdf/tests {@code xtest/vectors/assertions-phase0.json}.
 * Do not edit the copy here; regenerate it there and copy it again.
 * <p>
 * Every {@code required} vector must give exactly its expected result. {@code proposed} vectors
 * describe rules the specification has not settled; they run, and a mismatch is only logged.
 */
class AssertionVectorsTest {

    private static final String RESOURCE = "/assertion-vectors-phase0.json";
    private static final JsonObject DOCUMENT = load();

    private static JsonObject load() {
        try (InputStream in = Objects.requireNonNull(AssertionVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE)) {
            return JsonParser.parseString(new String(in.readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static Stream<Arguments> vectors() {
        List<Arguments> vectors = new ArrayList<>();
        for (var vector : DOCUMENT.getAsJsonArray("vectors")) {
            var object = vector.getAsJsonObject();
            vectors.add(Arguments.of(object.get("name").getAsString(), object));
        }
        return vectors.stream();
    }

    @Test
    void theFileIsTheSharedFormat() {
        assertThat(DOCUMENT.get("format").getAsString()).isEqualTo("opentdf-assertion-vectors/1");
        assertThat(DOCUMENT.getAsJsonArray("vectors")).isNotEmpty();
    }

    /** The file names the root level {@code ""}; Table 3.2 calls it the manifest root. */
    private static String fileLevel(String level) {
        return "manifest root".equals(level) ? "" : level;
    }

    private static Map<String, List<String>> stringLists(JsonObject json) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (var entry : json.entrySet()) {
            List<String> names = new ArrayList<>();
            entry.getValue().getAsJsonArray().forEach(name -> names.add(name.getAsString()));
            map.put(entry.getKey(), names);
        }
        return map;
    }

    @Test
    void theModelledNamesAreTheSharedTable() {
        Map<String, List<String>> java = new LinkedHashMap<>();
        StrictJsonReader.modelledNames().forEach((level, names) -> java.put(fileLevel(level), names));
        assertThat(java).isEqualTo(stringLists(DOCUMENT.getAsJsonObject("modelledNames")));

        Map<String, List<String>> exceptions = new LinkedHashMap<>();
        StrictJsonReader.caseVariantExceptions().forEach((level, names) -> exceptions.put(fileLevel(level), names));
        assertThat(exceptions).isEqualTo(stringLists(DOCUMENT.getAsJsonObject("caseVariantExceptions")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void vector(String name, JsonObject vector) throws Exception {
        JsonObject expected = vector.getAsJsonObject("expect");
        JsonObject actual = run(vector);
        if ("required".equals(vector.get("status").getAsString())) {
            assertThat(actual).as("%s: %s", name, vector.get("note").getAsString()).isEqualTo(expected);
        } else if (!actual.equals(expected)) {
            System.out.printf("proposed vector %s: expected %s, got %s (not enforced)%n", name, expected, actual);
        }
    }

    static Stream<Arguments> requiredAssertionVectors() {
        return vectors().filter(arguments -> {
            JsonObject vector = (JsonObject) arguments.get()[1];
            return "assertion".equals(vector.get("kind").getAsString())
                    && "required".equals(vector.get("status").getAsString())
                    // content after the object is not an assertion inside an array
                    && !"assertion-syntax-trailing-data".equals(vector.get("name").getAsString());
        });
    }

    /**
     * The same assertion vectors, read the way a TDF is read: spliced into a manifest, zipped,
     * and parsed by {@link SDK#readManifest}, with the hash and id taken from the result.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("requiredAssertionVectors")
    void assertionVectorThroughTheManifestReader(String name, JsonObject vector) throws Exception {
        byte[] assertion = vector.has("input")
                ? vector.get("input").getAsString().getBytes(StandardCharsets.UTF_8)
                : Base64.getDecoder().decode(vector.get("inputBase64").getAsString());
        String wrapper = StrictManifestParsingTest.manifest(",\"assertions\":[@]");
        int at = wrapper.indexOf('@');
        var manifest = new java.io.ByteArrayOutputStream();
        manifest.write(wrapper.substring(0, at).getBytes(StandardCharsets.UTF_8));
        manifest.write(assertion);
        manifest.write(wrapper.substring(at + 1).getBytes(StandardCharsets.UTF_8));
        byte[] tdf = StrictManifestParsingTest.tdfWithManifest(manifest.toByteArray());

        var result = new JsonObject();
        try {
            Manifest read = SDK.readManifest(new org.apache.commons.compress.utils.SeekableInMemoryByteChannel(tdf));
            JsonObject received = read.assertions.get(0).received();
            AssertionVerifier.exactId(received);
            String hash = AssertionJson.hash(received);
            // writing the manifest back out keeps the hash
            Manifest again = Manifest.readManifest(Manifest.toJson(read));
            assertThat(AssertionJson.hash(again.assertions.get(0).received())).as("round trip").isEqualTo(hash);
            result.addProperty("assertionHash", hash);
        } catch (SDK.AssertionFailureException e) {
            result.addProperty("reason", e.getReason().code());
        }
        assertThat(result).as("%s: %s", name, vector.get("note").getAsString()).isEqualTo(vector.getAsJsonObject("expect"));
    }

    /** What the reader does with one vector, as the vector's kind defines it. */
    private static JsonObject run(JsonObject vector) throws Exception {
        var result = new JsonObject();
        try {
            String input = vector.has("input")
                    ? vector.get("input").getAsString()
                    : AssertionJson.decodeUtf8(Base64.getDecoder().decode(vector.get("inputBase64").getAsString()));
            switch (vector.get("kind").getAsString()) {
                case "assertion": {
                    // Section 3 parsing, the 3.3 id check, then the public hash API
                    JsonObject assertion = AssertionJson.parseAssertion(input);
                    AssertionVerifier.exactId(assertion);
                    result.addProperty("assertionHash", Manifest.Assertion.computeAssertionHash(input));
                    break;
                }
                case "manifest":
                    Manifest.checkManifestJson(input);
                    result.addProperty("ok", true);
                    break;
                case "binding":
                    AssertionVerifier.jwsBinding(AssertionJson.parseAssertion(input), null);
                    result.addProperty("bindingForm", "jws");
                    break;
                case "verify": {
                    // Section 8, steps 3.3 to 3.9, with the key already selected
                    JsonObject assertion = AssertionJson.parseAssertion(input);
                    var key = key(vector.get("selectedKey").getAsString(), vector.get("keySource").getAsString());
                    AssertionVerifier.verifyWithKey(assertion, null, key,
                            Base64.getDecoder().decode(vector.get("aggregateHashBase64").getAsString()),
                            vector.get("legacy").getAsBoolean());
                    result.addProperty("ok", true);
                    break;
                }
                default:
                    throw new IllegalArgumentException("unknown vector kind " + vector.get("kind"));
            }
        } catch (SDK.AssertionFailureException e) {
            result = new JsonObject();
            result.addProperty("reason", e.getReason().code());
        }
        return result;
    }

    /**
     * The selected key, prepared the way the reader prepares it: a configured key goes through
     * the same checks as a configured {@link AssertionConfig.AssertionKey}, so the deliberately
     * unusable entries fail with {@code configuration-error}; the payload key is HS256.
     */
    private static AssertionVerifier.SelectedKey key(String name, String source) throws Exception {
        JsonObject entry = DOCUMENT.getAsJsonObject("keys").getAsJsonObject(name);
        Object material;
        if (entry.has("publicKeyPem")) {
            String pem = entry.get("publicKeyPem").getAsString()
                    .replaceAll("-----(BEGIN|END) PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            material = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
        } else {
            material = Base64.getDecoder().decode(entry.get("secretBase64").getAsString());
        }
        if ("payload".equals(source)) {
            return AssertionVerifier.SelectedKey.hmac((byte[]) material);
        }
        String alg = entry.get("alg").getAsString();
        // the enum holds only the supported names; anything else arrives as no algorithm
        AssertionConfig.AssertionKeyAlg keyAlg = "RS256".equals(alg) ? AssertionConfig.AssertionKeyAlg.RS256
                : "HS256".equals(alg) ? AssertionConfig.AssertionKeyAlg.HS256 : null;
        return AssertionVerifier.configuredKey(new AssertionConfig.AssertionKey(keyAlg, material), null, "the key " + name);
    }
}
