package io.opentdf.platform.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME;
import static io.opentdf.platform.sdk.TDFWriter.TDF_MANIFEST_FILE_NAME_SPEC;
import static io.opentdf.platform.sdk.TDFWriter.TDF_PAYLOAD_FILE_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class TDFValidatorTest {

    /** The SHA-256 of sdk/schema/manifest-lax.schema.json at opentdf/platform tag sdk/v0.35.0. */
    private static final String LAX_SCHEMA_SHA256 = "5e361720f005b23211a37d9e89c2c7ef51bc1b7df3353b82c2a568c3ed33f87d";

    /** The first lax-schema case: the smallest manifest the lax schema accepts. */
    private static final String MINIMAL_MANIFEST = "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\","
            + "\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{}}";

    private static final byte[] PAYLOAD = "ciphertext, unchecked".getBytes(StandardCharsets.UTF_8);

    // ---- the vendored schema

    /**
     * The schema must be the Go SDK's file, unedited. The sdk build filters resources, so this
     * also catches a refresh that the filter would change.
     */
    @Test
    void theLaxSchemaIsTheGoSdkFileUnchanged() throws IOException, NoSuchAlgorithmException {
        try (InputStream schema = TDFValidator.class.getResourceAsStream(TDFValidator.LAX_SCHEMA_RESOURCE)) {
            assertThat(schema).isNotNull();
            var digest = MessageDigest.getInstance("SHA-256").digest(schema.readAllBytes());
            assertThat(String.format("%064x", new BigInteger(1, digest))).isEqualTo(LAX_SCHEMA_SHA256);
        }
    }

    // ---- TDFs this SDK writes

    private static final KeyPair RSA_KAS_KEY = CryptoUtils.generateRSAKeypair();
    private static final KeyPair EC_KAS_KEY = CryptoUtils.generateECKeypair(KeyType.EC256Key.getECCurve().getCurveName());

    /** Hands out public keys, which is all writing a TDF needs; nothing here decrypts. */
    private static final SDK.KAS PUBLIC_KEY_KAS = new SDK.KAS() {
        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            var key = kasInfo.URL.endsWith("/ec") ? EC_KAS_KEY : RSA_KAS_KEY;
            var info = new Config.KASInfo();
            info.URL = kasInfo.URL;
            info.KID = "k1";
            info.PublicKey = CryptoUtils.getPublicKeyPEM(key.getPublic());
            return info;
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {
            throw new UnsupportedOperationException("validation must not unwrap keys");
        }

        @Override
        public KASKeyCache getKeyCache() {
            return new KASKeyCache();
        }

        @Override
        public void close() {
        }
    };

    private static Config.KASInfo kas(String url) {
        var info = new Config.KASInfo();
        info.URL = url;
        return info;
    }

    static Stream<Arguments> tdfsThisSdkWrites() {
        var rsa = kas("https://kas.example.com/rsa");
        var ec = kas("https://kas.example.com/ec");
        var assertion = new AssertionConfig();
        assertion.id = "assertion1";
        assertion.type = AssertionConfig.Type.BaseAssertion;
        assertion.scope = AssertionConfig.Scope.TrustedDataObj;
        assertion.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertion.statement = new AssertionConfig.Statement();
        assertion.statement.format = "base64binary";
        assertion.statement.schema = "text";
        assertion.statement.value = "ICAgIDxlZGoOkVkaD4=";
        assertion.signingKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                AesGcm.generateKey());
        return Stream.of(
                Arguments.of("RSA wrapped", "wrapped", List.<Consumer<Config.TDFConfig>>of(Config.withKasInformation(rsa))),
                Arguments.of("EC wrapped", "ec-wrapped", List.<Consumer<Config.TDFConfig>>of(
                        Config.withKasInformation(ec), Config.WithWrappingKeyAlg(KeyType.EC256Key))),
                Arguments.of("split across two KASes", "wrapped", List.<Consumer<Config.TDFConfig>>of(
                        Config.withKasInformation(rsa, kas("https://kas2.example.com/rsa")))),
                Arguments.of("assertions, metadata and a MIME type", "wrapped", List.<Consumer<Config.TDFConfig>>of(
                        Config.withKasInformation(rsa), Config.withAssertionConfig(assertion),
                        Config.withSystemMetadataAssertion(), Config.withMetaData("some metadata"),
                        Config.withMimeType("text/plain"))),
                Arguments.of("many segments", "wrapped", List.<Consumer<Config.TDFConfig>>of(
                        Config.withKasInformation(rsa), Config.withSegmentSize(Config.MIN_SEGMENT_SIZE))),
                Arguments.of("pre-4.3.0 target mode", "wrapped", List.<Consumer<Config.TDFConfig>>of(
                        Config.withKasInformation(rsa), Config.withTargetMode("4.2.2"))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("tdfsThisSdkWrites")
    void tdfsThisSdkWritesAreValid(String shape, String keyAccessType, List<Consumer<Config.TDFConfig>> options)
            throws Exception {
        var config = new ArrayList<Consumer<Config.TDFConfig>>(options);
        config.add(0, Config.withAutoconfigure(false));
        var tdfConfig = Config.newTDFConfig(config.toArray(Consumer[]::new));
        var out = new ByteArrayOutputStream();
        var payload = new byte[3 * Config.MIN_SEGMENT_SIZE + 17];
        var manifest = new TDF(new FakeServicesBuilder().setKas(PUBLIC_KEY_KAS).build())
                .createTDF(new ByteArrayInputStream(payload), out, tdfConfig).getManifest();
        // the shape is the one named
        assertThat(manifest.encryptionInformation.keyAccessObj).extracting(k -> k.keyType).containsOnly(keyAccessType);

        SDK.validateTdf(new SeekableInMemoryByteChannel(out.toByteArray()));
        assertThat(SDK.isValidTdf(new SeekableInMemoryByteChannel(out.toByteArray()))).isTrue();
    }

    @Test
    void theSampleTdfIsValid() throws IOException {
        try (var tdf = Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream("sample.txt.tdf"))) {
            assertThat(SDK.isValidTdf(new SeekableInMemoryByteChannel(tdf.readAllBytes()))).isTrue();
        }
    }

    // ---- the lax schema

    static Stream<Arguments> laxSchemaCases() throws IOException {
        try (var cases = new InputStreamReader(Objects.requireNonNull(
                TDFValidatorTest.class.getResourceAsStream("lax-manifest-cases.json")), StandardCharsets.UTF_8)) {
            var corpus = JsonParser.parseReader(cases).getAsJsonObject().getAsJsonArray("cases");
            var arguments = new ArrayList<Arguments>();
            for (JsonElement element : corpus) {
                JsonObject c = element.getAsJsonObject();
                arguments.add(Arguments.of(c.get("name").getAsString(), c.get("manifest").toString(),
                        c.get("valid").getAsBoolean()));
            }
            assertThat(arguments).hasSize(42);
            return arguments.stream();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("laxSchemaCases")
    void laxSchemaCasesGetTheGoSdkAnswer(String name, String manifest, boolean valid) throws IOException {
        assertThat(SDK.isValidTdf(tdfWithManifest(manifest))).as(name).isEqualTo(valid);
    }

    @Test
    void aSchemaFailureNamesWhereInTheManifestItIs() {
        var manifest = MINIMAL_MANIFEST.replace("\"isEncrypted\":true", "\"isEncrypted\":\"yes\"");
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(manifest)))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest does not match the lax manifest schema at /payload/isEncrypted: ")
                .hasMessageNotContaining("\n");
    }

    @Test
    void aManifestThatIsNotAnObjectIsReportedAtTheTopLevel() {
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest("[]")))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest does not match the lax manifest schema at the top level: ");
    }

    /**
     * Known divergence, pinned so that it is noticed when it changes: the lax schema's key access
     * type enum has no {@code mlkem-wrapped}, which this SDK (with sdk-pqc-bc), Go and the web SDK
     * all write. DSPX-4388 tracks fixing the schema; this flips when a refreshed schema lands.
     */
    @Test
    void mlkemWrappedKeyAccessIsNotInTheLaxSchemaYet() {
        var manifest = MINIMAL_MANIFEST.replace("\"encryptionInformation\":{}",
                "\"encryptionInformation\":{\"keyAccess\":[{\"type\":\"mlkem-wrapped\",\"url\":\"https://kas.example.com\","
                        + "\"protocol\":\"kas\",\"wrappedKey\":\"AAAA\",\"policyBinding\":\"AAAA\"}]}");
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(manifest)))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("/encryptionInformation/keyAccess/0/type");
    }

    // ---- choosing the manifest

    @Test
    void theSpecManifestNameIsAccepted() throws IOException {
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD),
                entry(TDF_MANIFEST_FILE_NAME_SPEC, MINIMAL_MANIFEST)))).isTrue();
    }

    @Test
    void theSpecManifestNameWinsWhenBothArePresent() throws IOException {
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(TDF_MANIFEST_FILE_NAME, "{}"),
                entry(TDF_MANIFEST_FILE_NAME_SPEC, MINIMAL_MANIFEST)))).isTrue();
    }

    /** A failing manifest.json is not retried as 0.manifest.json, which would read a superseded manifest. */
    @Test
    void thereIsNoFallbackWhenTheSpecManifestFails() throws IOException {
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD),
                entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST), entry(TDF_MANIFEST_FILE_NAME_SPEC, "{}")))).isFalse();
    }

    /**
     * An archive listing one name twice is refused, as {@link TDFReader} refuses it, in either
     * order. Go and the web SDK let the last copy win instead; refusing is what DSPX-4924 asks
     * for, since two readers that pick different copies read different policies from one file.
     */
    @ParameterizedTest
    @ValueSource(strings = {TDF_MANIFEST_FILE_NAME_SPEC, TDF_MANIFEST_FILE_NAME})
    void aDuplicatedManifestEntryIsInvalidInEitherOrder(String name) {
        for (var order : List.of(List.of("{}", MINIMAL_MANIFEST), List.of(MINIMAL_MANIFEST, "{}"))) {
            var channel = tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(name, order.get(0)), entry(name, order.get(1)));
            assertThatThrownBy(() -> SDK.validateTdf(channel))
                    .isInstanceOf(SDK.MalformedTDFException.class)
                    .hasMessageContaining("more than one entry named " + name);
        }
    }

    @Test
    void aDuplicatedPayloadEntryIsInvalid() throws IOException {
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD),
                entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST)))).isFalse();
    }

    @Test
    void anUnrelatedExtraEntryIsIgnored() throws IOException {
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD),
                entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST), entry("something-else", "x")))).isTrue();
    }

    @Test
    void aMissingManifestIsInvalid() {
        assertThatThrownBy(() -> SDK.validateTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD))))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("doesn't contain a manifest");
    }

    /**
     * Java's reader needs a payload entry, so the check does too. Go's {@code IsValidTdf} and the
     * web SDK's {@code isValidTdf} accept a manifest alone.
     */
    @Test
    void aMissingPayloadIsInvalid() {
        assertThatThrownBy(() -> SDK.validateTdf(tdf(entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST))))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("doesn't contain a payload");
    }

    /** The payload is not read, let alone decrypted or checked against the manifest. */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 28})
    void thePayloadIsNotChecked(int payloadSize) throws IOException {
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, new byte[payloadSize]),
                entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST)))).isTrue();
    }

    // ---- parsing the manifest

    @ParameterizedTest
    @ValueSource(strings = {TDF_MANIFEST_FILE_NAME_SPEC, TDF_MANIFEST_FILE_NAME})
    void aByteOrderMarkIsInvalid(String name) {
        var withBom = HostileZips.concat(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF},
                MINIMAL_MANIFEST.getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> SDK.validateTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(name, withBom))))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessage("manifest starts with a byte order mark");
    }

    @ParameterizedTest
    @ValueSource(strings = {" {}", "{}", "x", "\u0000", " []", "\"more\""})
    void dataAfterTheManifestIsInvalid(String trailing) {
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(MINIMAL_MANIFEST + trailing)))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest has data after its JSON value, starting at line 1 column ")
                .hasMessageNotContaining("LENIENT");
    }

    @Test
    void whitespaceAroundTheManifestIsAllowed() throws IOException {
        assertThat(SDK.isValidTdf(tdfWithManifest(" \t\r\n" + MINIMAL_MANIFEST + "\n \t\r\n"))).isTrue();
    }

    /** What Gson's lenient default accepts, and RFC 8259 and Go do not. */
    @ParameterizedTest
    @ValueSource(strings = {
            "{/* a comment */\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{}}",
            "{'payload':{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{}}",
            "{payload:{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{}}",
            "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{},}",
            "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":TRUE},\"encryptionInformation\":{}}",
            "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{},\"n\":NaN}",
            "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{},\"s\":\"\\'\"}",
            "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{},\"s\":\"a\tb\"}",
            "{\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true};\"encryptionInformation\":{}}",
            "{\"payload\"=>{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true},\"encryptionInformation\":{}}",
            ")]}'\n" + MINIMAL_MANIFEST,
    })
    void lenientJsonIsInvalid(String manifest) {
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(manifest)))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest is not valid JSON: ")
                .hasMessageNotContaining("LENIENT")
                .hasMessageNotContaining("\n");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "{", "{\"payload\":", "nul"})
    void emptyOrTruncatedJsonIsInvalid(String manifest) {
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(manifest)))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest is not valid JSON: ");
    }

    /** Go's limit: 10,000 levels are accepted, 10,001 are not. The object around the arrays is one level. */
    @Test
    void nestingIsLimitedToGosDepth() throws IOException {
        int arrays = TDFValidator.MAX_NESTING_DEPTH - 1;
        assertThat(SDK.isValidTdf(tdfWithManifest(withMember("\"deep\":" + "[".repeat(arrays) + "]".repeat(arrays)))))
                .isTrue();
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(
                withMember("\"deep\":" + "[".repeat(arrays + 1) + "]".repeat(arrays + 1)))))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest is not valid JSON: ");
    }

    /** As in Go, a repeated member name is not an error and the last one wins. */
    @Test
    void theLastOfARepeatedMemberWins() throws IOException {
        var payload = "\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\",\"isEncrypted\":true}";
        assertThat(SDK.isValidTdf(tdfWithManifest("{\"payload\":1," + payload + ",\"encryptionInformation\":{}}")))
                .isTrue();
        assertThat(SDK.isValidTdf(tdfWithManifest("{" + payload + ",\"payload\":1,\"encryptionInformation\":{}}")))
                .isFalse();
    }

    /** As in Go, bytes that are not UTF-8 become U+FFFD rather than failing the parse. */
    @Test
    void malformedUtf8InAStringIsReplacedNotRefused() throws IOException {
        // "zip" becomes "zi" followed by a byte that can't start a UTF-8 sequence
        int p = MINIMAL_MANIFEST.indexOf("\"zip\"") + 3;
        var manifest = HostileZips.concat(MINIMAL_MANIFEST.substring(0, p).getBytes(StandardCharsets.UTF_8),
                new byte[]{(byte) 0xFF}, MINIMAL_MANIFEST.substring(p + 1).getBytes(StandardCharsets.UTF_8));
        assertThat(SDK.isValidTdf(tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(TDF_MANIFEST_FILE_NAME, manifest))))
                .isTrue();
    }

    /**
     * Gson will not convert a number of more than 10,000 digits, or with an exponent that large,
     * so the validator fails on one where the schema looks. That is reported as invalid, not
     * thrown. Go accepts such a number.
     */
    @Test
    void aNumberGsonWontConvertIsInvalidNotThrown() {
        var manifest = MINIMAL_MANIFEST.replace("\"isEncrypted\":true", "\"isEncrypted\":true,\"big\":1e99999");
        assertThatThrownBy(() -> SDK.validateTdf(tdfWithManifest(manifest)))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest could not be checked against the lax manifest schema: ");
    }

    // ---- archive structure

    /**
     * Java's reader accepts an archive comment, and so does this check. Go's {@code IsValidTdf}
     * refuses one; that divergence is the epic's to settle (DSPX-5348).
     */
    @Test
    void anArchiveCommentIsAllowed() throws IOException {
        var archive = HostileZips.build(List.of(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST)));
        var comment = "an archive comment".getBytes(StandardCharsets.UTF_8);
        // the comment length is the last field of the end of central directory record
        archive[archive.length - 2] = (byte) comment.length;
        assertThat(SDK.isValidTdf(new SeekableInMemoryByteChannel(HostileZips.concat(archive, comment)))).isTrue();
    }

    @Test
    void anEmptyChannelIsInvalid() throws IOException {
        assertThat(SDK.isValidTdf(new SeekableInMemoryByteChannel(new byte[0]))).isFalse();
    }

    @Test
    void bytesThatAreNotAZipAreInvalid() throws IOException {
        assertThat(SDK.isValidTdf(new SeekableInMemoryByteChannel(MINIMAL_MANIFEST.getBytes(StandardCharsets.UTF_8))))
                .isFalse();
    }

    @Test
    void aTruncatedArchiveIsInvalid() throws IOException {
        var whole = HostileZips.build(List.of(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST)));
        for (int cut = 1; cut < whole.length; cut++) {
            var truncated = Arrays.copyOf(whole, whole.length - cut);
            assertThat(SDK.isValidTdf(new SeekableInMemoryByteChannel(truncated))).as("cut %d bytes", cut).isFalse();
        }
    }

    /**
     * A manifest entry that claims more bytes than it has reads on into the next zip record, which
     * is not JSON. (The archive can't run out first: the end of central directory record is last.)
     */
    @Test
    void aManifestEntryClaimingMoreBytesThanItHasIsInvalid() {
        var manifest = entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST);
        manifest.uncompressedSize = (long) MINIMAL_MANIFEST.length() + 4096;
        assertThatThrownBy(() -> SDK.validateTdf(new SeekableInMemoryByteChannel(
                HostileZips.build(List.of(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), manifest)))))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageStartingWith("manifest has data after its JSON value, starting at line 1 column ");
    }

    @Test
    void hostileCentralDirectoriesAreInvalid() {
        HostileZips.hostileShapes().forEach((shape, hostile) -> {
            var archive = HostileZips.tdfWith(MINIMAL_MANIFEST, hostile);
            boolean valid = assertTimeoutPreemptively(Duration.ofSeconds(5),
                    () -> SDK.isValidTdf(new SeekableInMemoryByteChannel(archive)), shape);
            assertThat(valid).as(shape).isFalse();
        });
    }

    /**
     * Every input the reader's fuzz targets have kept gets an answer: no hang, and no exception,
     * since an in-memory channel never fails to read.
     */
    @ParameterizedTest
    @ValueSource(strings = {"fuzzTDF", "fuzzZipRead"})
    void everyFuzzingInputGetsAnAnswer(String target) throws IOException, URISyntaxException {
        var inputs = Paths.get(Objects.requireNonNull(getClass().getResource("FuzzingInputs/" + target)).toURI());
        try (Stream<Path> files = Files.list(inputs)) {
            for (var file : (Iterable<Path>) files::iterator) {
                var bytes = Files.readAllBytes(file);
                assertTimeoutPreemptively(Duration.ofSeconds(5),
                        () -> SDK.isValidTdf(new SeekableInMemoryByteChannel(bytes)), file.toString());
            }
        }
    }

    // ---- I/O errors

    @Test
    void aChannelThatCannotBeReadThrows() {
        var channel = new SeekableInMemoryByteChannel(HostileZips.tdfWith(MINIMAL_MANIFEST, e -> { })) {
            @Override
            public int read(ByteBuffer buf) throws IOException {
                throw new IOException("disk on fire");
            }
        };
        assertThatThrownBy(() -> SDK.isValidTdf(channel)).isInstanceOf(IOException.class).hasMessage("disk on fire");
    }

    /** A read failure part way through the manifest is an I/O error too, not an invalid manifest. */
    @Test
    void aReadFailureInsideTheManifestThrows() {
        var manifestName = TDF_MANIFEST_FILE_NAME.getBytes(StandardCharsets.UTF_8);
        // the manifest is the first entry, so its data starts right after its local header
        long manifestStart = 30 + manifestName.length;
        var archive = HostileZips.build(List.of(entry(TDF_MANIFEST_FILE_NAME, MINIMAL_MANIFEST), entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD)));
        var channel = new SeekableInMemoryByteChannel(archive) {
            @Override
            public int read(ByteBuffer buf) throws IOException {
                if (position() >= manifestStart && position() < manifestStart + MINIMAL_MANIFEST.length()) {
                    throw new IOException("disk on fire");
                }
                return super.read(buf);
            }
        };
        assertThatThrownBy(() -> SDK.isValidTdf(channel)).isInstanceOf(IOException.class).hasMessage("disk on fire");
    }

    @Test
    void aChannelThatStallsThrows() {
        var channel = new SeekableInMemoryByteChannel(HostileZips.tdfWith(MINIMAL_MANIFEST, e -> { })) {
            @Override
            public int read(ByteBuffer buf) {
                return 0;
            }
        };
        assertThatThrownBy(() -> SDK.isValidTdf(channel)).isInstanceOf(IOException.class)
                .hasMessageContaining("returned no data");
    }

    // ---- helpers

    private static String withMember(String member) {
        return MINIMAL_MANIFEST.substring(0, MINIMAL_MANIFEST.length() - 1) + "," + member + "}";
    }

    private static HostileZips.Entry entry(String name, String data) {
        return entry(name, data.getBytes(StandardCharsets.UTF_8));
    }

    private static HostileZips.Entry entry(String name, byte[] data) {
        return new HostileZips.Entry(name, data);
    }

    private static SeekableInMemoryByteChannel tdf(HostileZips.Entry... entries) {
        return new SeekableInMemoryByteChannel(HostileZips.build(List.of(entries)));
    }

    /** A payload, then the given manifest under the name this SDK writes. */
    private static SeekableInMemoryByteChannel tdfWithManifest(String manifest) {
        return tdf(entry(TDF_PAYLOAD_FILE_NAME, PAYLOAD), entry(TDF_MANIFEST_FILE_NAME, manifest));
    }
}
