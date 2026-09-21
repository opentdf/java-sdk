package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The root signature is the only thing in a ZTDF that authenticates the
 * <em>manifest's</em> description of the payload: the ordered list of segment hashes.
 * Per-segment AES-GCM tags authenticate each segment's bytes in isolation, but nothing
 * in a segment binds it to its index or to the total segment count, so a manifest that
 * lies about the segment list is only caught by the root signature.
 * <p>
 * A "GMAC" root signature is not a MAC. GMAC over a segment's ciphertext recovers the
 * tag AES-GCM already produced over those exact bytes, which is a genuine authenticator;
 * over the aggregate hash there is no such tag, and the trailing sixteen bytes are just
 * a copy of the last segment hash — attacker-supplied manifest data, no key involved.
 * Since {@code rootSignature.alg} is itself read from the unauthenticated manifest, any
 * reader that honours GMAC there can be downgraded onto that branch by someone holding
 * no key at all, and can then be fed a truncated or reordered segment list.
 * <p>
 * These tests pin that boundary. The controls establish that tampering is caught in the
 * ordinary HS256 case — without them the exploit cases would prove nothing — and the
 * exploit cases establish that the keyless downgrade is now refused.
 */
class TDFRootSignatureTest {

    /** Small segments keep the fixtures cheap while still giving several of them. */
    private static final int SEGMENT_SIZE = Config.MIN_SEGMENT_SIZE;
    private static final String KAS_URL = "https://example.com/kas0";

    private static KeyPair kasKeyPair;

    private static final SDK.KAS KAS = new SDK.KAS() {
        @Override
        public void close() {
            // no-op: nothing to release in this fake
        }

        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            var resolved = new Config.KASInfo();
            resolved.URL = kasInfo.URL;
            resolved.KID = "r1";
            resolved.PublicKey = CryptoUtils.getPublicKeyPEM(kasKeyPair.getPublic());
            return resolved;
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {
            return new AsymDecryption(kasKeyPair.getPrivate())
                    .decrypt(Base64.getDecoder().decode(keyAccess.wrappedKey));
        }

        @Override
        public KASKeyCache getKeyCache() {
            return new KASKeyCache();
        }
    };

    @BeforeAll
    static void generateKasKeyPair() {
        kasKeyPair = CryptoUtils.generateRSAKeypair();
    }

    // ---------------------------------------------------------------- controls

    @Test
    void untouchedTdfRoundTrips() throws IOException {
        // Also a control on the test harness itself: unzipping and rezipping a TDF
        // without editing it must not disturb anything the reader checks.
        var plaintext = fourSegmentPlaintext();
        var rewritten = rewrite(createTdf(plaintext), manifest -> {
        }, UnaryOperator.identity());

        assertThat(decrypt(rewritten)).containsExactly(plaintext);
    }

    @Test
    void truncationUnderHs256IsCaught() throws IOException {
        var tampered = rewrite(createTdf(fourSegmentPlaintext()),
                manifest -> keepSegments(manifest, 2),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void segmentHashEditUnderHs256IsCaught() throws IOException {
        var tampered = rewrite(createTdf(fourSegmentPlaintext()), manifest -> {
            var first = segments(manifest).get(0).getAsJsonObject();
            var hash = Base64.getDecoder().decode(first.get("hash").getAsString());
            hash[0] ^= 0xFF;
            first.addProperty("hash", Base64.getEncoder().encodeToString(hash));
        }, UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void reorderUnderHs256IsCaught() throws IOException {
        var original = createTdf(fourSegmentPlaintext());
        var sizes = encryptedSegmentSizes(original);

        var tampered = rewrite(original,
                TDFRootSignatureTest::reverseSegments,
                payload -> reverseChunks(payload, sizes));

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void gmacDowngradeWithoutForgedSignatureIsCaught() throws IOException {
        // Isolates the downgrade itself from the forged signature: flipping `alg` alone
        // must not validate.
        var tampered = rewrite(createTdf(fourSegmentPlaintext()),
                manifest -> rootSignature(manifest).addProperty("alg", "GMAC"),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @ParameterizedTest
    @EnumSource(Config.IntegrityAlgorithm.class)
    void segmentTagTamperIsCaughtBySegmentHash(Config.IntegrityAlgorithm algorithm) throws IOException {
        // The manifest is untouched, so the root signature still verifies; the segment
        // hash is what has to catch this. Flipping the final payload byte hits the last
        // segment's GCM tag, which is the segment hash itself under GMAC and is covered
        // by the HMAC under HS256.
        var tampered = rewrite(createTdf(fourSegmentPlaintext(), withSegmentAlgorithm(algorithm)),
                manifest -> {
                }, payload -> flipByte(payload, payload.length - 1));

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.SegmentSignatureMismatch.class);
    }

    // ---------------------------------------------------------------- exploits

    @Test
    void gmacRootIsRejected() throws IOException {
        // The whole segment list is intact and the signature is exactly what the GMAC
        // branch used to compute, so this is the best-case forgery. It must still fail:
        // a GMAC root signature carries no authentication at all.
        var tampered = rewrite(createTdf(fourSegmentPlaintext()),
                manifest -> forgeGmacRootSignature(manifest, "GMAC"),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = { "GMAC", "gmac", "GMac", " GMAC " })
    void gmacRootIsRejectedInAnyCasing(String declaredAlgorithm) throws IOException {
        // Casing is the cheapest way around a case-sensitive rejection, so pin it.
        var tampered = rewrite(createTdf(fourSegmentPlaintext()),
                manifest -> forgeGmacRootSignature(manifest, declaredAlgorithm),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void gmacDowngradeWithTruncatedSegmentsIsRejected() throws IOException {
        // The exploit: a keyless attacker declares GMAC, drops the trailing segments,
        // and recomputes the "signature" from manifest data it already controls. The
        // payload entry still holds every segment's ciphertext; the reader walks the
        // manifest, so the trailing bytes are simply never read.
        var plaintext = fourSegmentPlaintext();
        var tampered = rewrite(createTdf(plaintext), manifest -> {
            keepSegments(manifest, 2);
            forgeGmacRootSignature(manifest, "GMAC");
        }, UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void gmacDowngradeWithReorderedSegmentsIsRejected() throws IOException {
        // Same downgrade applied to segment order. Reordering needs the ciphertext moved
        // too, since the reader walks the payload sequentially -- but that is still a
        // keyless edit, and every segment keeps its own valid GCM tag. Nothing in AES-GCM
        // binds a segment to its index, so per-segment authentication cannot notice the
        // permutation.
        var original = createTdf(fourSegmentPlaintext());
        var sizes = encryptedSegmentSizes(original);

        var tampered = rewrite(original, manifest -> {
            reverseSegments(manifest);
            forgeGmacRootSignature(manifest, "GMAC");
        }, payload -> reverseChunks(payload, sizes));

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void unknownRootAlgorithmIsRejected() throws IOException {
        // Fail closed: an algorithm the reader does not implement must be refused rather
        // than quietly treated as HS256.
        var tampered = rewrite(createTdf(fourSegmentPlaintext()),
                manifest -> rootSignature(manifest).addProperty("alg", "HS512"),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    @Test
    void unknownSegmentAlgorithmIsRejected() throws IOException {
        // `segmentHashAlg` is not covered by the root signature, so it has to be
        // allowlisted on its own. Exactly a TamperException, not the
        // SegmentSignatureMismatch subtype: nothing here compared a signature.
        var tampered = rewrite(createTdf(fourSegmentPlaintext()),
                manifest -> integrityInformation(manifest).addProperty("segmentHashAlg", "MD5"),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isExactlyInstanceOf(SDK.TamperException.class);
    }

    // ------------------------------------------------------- segment algorithms

    @ParameterizedTest
    @EnumSource(Config.IntegrityAlgorithm.class)
    void segmentAlgorithmRoundTrips(Config.IntegrityAlgorithm algorithm) throws IOException {
        // GMAC segments must keep working: every TDF in existence uses them.
        var plaintext = fourSegmentPlaintext();
        var tdfBytes = createTdf(plaintext, withSegmentAlgorithm(algorithm));

        var integrityInformation = integrityInformation(JsonParser.parseString(manifestOf(tdfBytes))
                .getAsJsonObject());
        assertThat(integrityInformation.get("segmentHashAlg").getAsString()).isEqualTo(algorithm.name());
        assertThat(integrityInformation.getAsJsonObject("rootSignature").get("alg").getAsString())
                .isEqualTo(Config.IntegrityAlgorithm.HS256.name());

        int expectedHashLength = algorithm == Config.IntegrityAlgorithm.GMAC ? 16 : 32;
        for (var segment : integrityInformation.getAsJsonArray("segments")) {
            assertThat(Base64.getDecoder().decode(segment.getAsJsonObject().get("hash").getAsString()))
                    .hasSize(expectedHashLength);
        }

        assertThat(decrypt(tdfBytes)).containsExactly(plaintext);
    }

    @ParameterizedTest
    @EnumSource(Config.IntegrityAlgorithm.class)
    void segmentBodyTamperIsCaughtUnderEitherSegmentAlgorithm(Config.IntegrityAlgorithm algorithm) throws IOException {
        // A flip in the middle of a segment's ciphertext is caught in different places
        // depending on the algorithm -- by the segment hash under HS256, and by AES-GCM's
        // own tag check at decryption time under GMAC, where the segment hash is that
        // same tag and so is unchanged. Either way the read fails.
        var tdfBytes = createTdf(fourSegmentPlaintext(), withSegmentAlgorithm(algorithm));
        var tampered = rewrite(tdfBytes, manifest -> {
        }, payload -> flipByte(payload, payload.length / 2));

        assertThatThrownBy(() -> decrypt(tampered)).isInstanceOf(SDKException.class);
    }

    @Test
    void defaultsAreHs256RootAndGmacSegments() throws IOException {
        var integrityInformation = integrityInformation(
                JsonParser.parseString(manifestOf(createTdf(fourSegmentPlaintext()))).getAsJsonObject());

        assertThat(integrityInformation.getAsJsonObject("rootSignature").get("alg").getAsString())
                .isEqualTo("HS256");
        assertThat(integrityInformation.get("segmentHashAlg").getAsString()).isEqualTo("GMAC");
    }

    // ------------------------------------------------------------ legacy 4.2.2

    @ParameterizedTest
    @EnumSource(Config.IntegrityAlgorithm.class)
    void legacyHexEncodedRootStillValidates(Config.IntegrityAlgorithm segmentAlgorithm) throws IOException {
        // 4.2.x files hex-encode the root signature and each segment hash before base64.
        // Splitting calculateSignature must not have disturbed that.
        var plaintext = fourSegmentPlaintext();
        var tdfBytes = createTdf(plaintext,
                Config.withTargetMode("4.2.2"),
                withSegmentAlgorithm(segmentAlgorithm));

        var manifest = JsonParser.parseString(manifestOf(tdfBytes)).getAsJsonObject();
        assertThat(manifest.has("schemaVersion")).isFalse();
        var integrityInformation = integrityInformation(manifest);
        var rootSignature = Base64.getDecoder()
                .decode(integrityInformation.getAsJsonObject("rootSignature").get("sig").getAsString());
        assertThat(new String(rootSignature, StandardCharsets.UTF_8)).matches("[0-9a-f]{64}");

        assertThat(decrypt(tdfBytes)).containsExactly(plaintext);
    }

    @Test
    void legacyGmacRootIsRejected() throws IOException {
        // The legacy hex-encoding path must not become a way around the allowlist.
        var tampered = rewrite(createTdf(fourSegmentPlaintext(), Config.withTargetMode("4.2.2")),
                manifest -> rootSignature(manifest).addProperty("alg", "GMAC"),
                UnaryOperator.identity());

        assertThatThrownBy(() -> decrypt(tampered))
                .isInstanceOf(SDK.RootSignatureValidationException.class);
    }

    // ------------------------------------------------------------------ config

    @Test
    void createTdfRefusesAGmacRootSetDirectlyOnTheConfig() {
        // Config offers no way to select the root algorithm, but TDFConfig's fields are
        // public, so the writer re-checks rather than trusting the default.
        var config = tdfConfig();
        config.integrityAlgorithm = Config.IntegrityAlgorithm.GMAC;

        var tdf = tdf();
        var payload = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8));
        var output = new ByteArrayOutputStream();

        assertThatThrownBy(() -> tdf.createTDF(payload, output, config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported root integrity algorithm");
    }

    @Test
    void createTdfRefusesAnUnsetSegmentAlgorithm() {
        // Same reasoning as above, for the segment field: public and therefore nullable.
        // Caught before any output is written rather than as a NullPointerException
        // partway through the payload.
        var config = tdfConfig();
        config.segmentIntegrityAlgorithm = null;

        var tdf = tdf();
        var payload = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8));
        var output = new ByteArrayOutputStream();

        assertThatThrownBy(() -> tdf.createTDF(payload, output, config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported segment integrity algorithm");
        assertThat(output.size()).isZero();
    }

    // ------------------------------------------------------- guards, called directly

    /*
     * The manifest resolvers above are what a hostile file actually meets, and the
     * round-trip tests cover them. These call the inner guards directly because nothing
     * else does: with the resolvers in place a GMAC root cannot reach `rootIntegrity`,
     * so without these a regression that reintroduced tag extraction there would leave
     * the whole suite green. Defence in depth is only depth if the inner layer is held
     * to its contract independently.
     */

    @Test
    void rootIntegrityRefusesGmacWhenCalledDirectly() {
        assertThatThrownBy(() -> TDF.rootIntegrity(new byte[64], new byte[32], Config.IntegrityAlgorithm.GMAC))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported root integrity algorithm");
    }

    @Test
    void rootIntegrityRefusesNullWhenCalledDirectly() {
        assertThatThrownBy(() -> TDF.rootIntegrity(new byte[64], new byte[32], null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported root integrity algorithm");
    }

    @Test
    void rootIntegrityAcceptsHs256() {
        assertThat(TDF.rootIntegrity(new byte[64], new byte[32], Config.IntegrityAlgorithm.HS256))
                .hasSize(32);
    }

    @Test
    void segmentIntegrityRefusesNullWhenCalledDirectly() {
        assertThatThrownBy(() -> TDF.segmentIntegrity(new byte[64], new byte[32], null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported segment integrity algorithm");
    }

    // ----------------------------------------------------------------- fixtures

    /**
     * Three full segments and a partial one, each filled with a distinct byte so a
     * reordered or truncated decryption would be visible in the output and not only in
     * an error. Deliberately not an exact multiple of the segment size, which would add
     * a trailing empty segment.
     */
    private static byte[] fourSegmentPlaintext() {
        var plaintext = new byte[3 * SEGMENT_SIZE + SEGMENT_SIZE / 2];
        for (int index = 0; index < plaintext.length; index++) {
            plaintext[index] = (byte) ('A' + index / SEGMENT_SIZE);
        }
        return plaintext;
    }

    private static TDF tdf() {
        return new TDF(new FakeServicesBuilder().setKas(KAS).build());
    }

    /**
     * Writers get GMAC segment hashes and nothing else -- Config has no setter for this.
     * These tests reach past that to cover the HS256 segments other implementations
     * write and this SDK must still read.
     */
    private static Consumer<Config.TDFConfig> withSegmentAlgorithm(Config.IntegrityAlgorithm algorithm) {
        return config -> config.segmentIntegrityAlgorithm = algorithm;
    }

    @SafeVarargs
    private static Config.TDFConfig tdfConfig(Consumer<Config.TDFConfig>... extras) {
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = KAS_URL;

        var options = new ArrayList<Consumer<Config.TDFConfig>>(List.of(
                Config.withAutoconfigure(false),
                Config.withKasInformation(kasInfo),
                Config.withSegmentSize(SEGMENT_SIZE)));
        Collections.addAll(options, extras);

        @SuppressWarnings("unchecked")
        Consumer<Config.TDFConfig>[] asArray = options.toArray(new Consumer[0]);
        return Config.newTDFConfig(asArray);
    }

    @SafeVarargs
    private static byte[] createTdf(byte[] plaintext, Consumer<Config.TDFConfig>... extras) throws IOException {
        var tdfBytes = new ByteArrayOutputStream();
        tdf().createTDF(new ByteArrayInputStream(plaintext), tdfBytes, tdfConfig(extras));
        return tdfBytes.toByteArray();
    }

    private static byte[] decrypt(byte[] tdfBytes) throws IOException {
        var reader = tdf().loadTDF(new SeekableInMemoryByteChannel(tdfBytes),
                Config.newTDFReaderConfig(Config.WithIgnoreKasAllowlist(true)));
        var plaintext = new ByteArrayOutputStream();
        reader.readPayload(plaintext);
        return plaintext.toByteArray();
    }

    // ------------------------------------------------------- manifest surgery

    private static JsonObject integrityInformation(JsonObject manifest) {
        return manifest.getAsJsonObject("encryptionInformation").getAsJsonObject("integrityInformation");
    }

    private static JsonObject rootSignature(JsonObject manifest) {
        return integrityInformation(manifest).getAsJsonObject("rootSignature");
    }

    private static JsonArray segments(JsonObject manifest) {
        return integrityInformation(manifest).getAsJsonArray("segments");
    }

    private static void keepSegments(JsonObject manifest, int count) {
        var kept = new JsonArray();
        var all = segments(manifest);
        for (int index = 0; index < count; index++) {
            kept.add(all.get(index));
        }
        integrityInformation(manifest).add("segments", kept);
    }

    private static void reverseSegments(JsonObject manifest) {
        var reversed = new JsonArray();
        var all = segments(manifest);
        for (int index = all.size() - 1; index >= 0; index--) {
            reversed.add(all.get(index));
        }
        integrityInformation(manifest).add("segments", reversed);
    }

    /**
     * Rewrites the root signature exactly the way an attacker with no key can: declare
     * GMAC, then emit the trailing sixteen bytes of the aggregate hash. Every input is
     * manifest data the attacker already controls.
     */
    private static void forgeGmacRootSignature(JsonObject manifest, String declaredAlgorithm) {
        var aggregate = new ByteArrayOutputStream();
        for (var segment : segments(manifest)) {
            var hash = Base64.getDecoder().decode(segment.getAsJsonObject().get("hash").getAsString());
            aggregate.write(hash, 0, hash.length);
        }

        var bytes = aggregate.toByteArray();
        var forged = new byte[16];
        System.arraycopy(bytes, bytes.length - forged.length, forged, 0, forged.length);

        var rootSignature = rootSignature(manifest);
        rootSignature.addProperty("alg", declaredAlgorithm);
        rootSignature.addProperty("sig", Base64.getEncoder().encodeToString(forged));
    }

    private static List<Integer> encryptedSegmentSizes(byte[] tdfBytes) throws IOException {
        var sizes = new ArrayList<Integer>();
        for (var segment : segments(JsonParser.parseString(manifestOf(tdfBytes)).getAsJsonObject())) {
            sizes.add(segment.getAsJsonObject().get("encryptedSegmentSize").getAsInt());
        }
        return sizes;
    }

    private static byte[] flipByte(byte[] payload, int index) {
        var copy = payload.clone();
        copy[index] ^= 0xFF;
        return copy;
    }

    private static byte[] reverseChunks(byte[] payload, List<Integer> sizes) {
        var reversed = new byte[payload.length];
        int destination = 0;
        int sourceEnd = payload.length;
        for (int index = sizes.size() - 1; index >= 0; index--) {
            int size = sizes.get(index);
            System.arraycopy(payload, sourceEnd - size, reversed, destination, size);
            destination += size;
            sourceEnd -= size;
        }
        return reversed;
    }

    // ------------------------------------------------------------ zip plumbing

    private static String manifestOf(byte[] tdfBytes) throws IOException {
        return new String(entry(tdfBytes, TDFWriter.TDF_MANIFEST_FILE_NAME), StandardCharsets.UTF_8);
    }

    private static byte[] entry(byte[] tdfBytes, String name) throws IOException {
        for (var entry : new ZipReader(new SeekableInMemoryByteChannel(tdfBytes)).getEntries()) {
            if (entry.getName().equals(name)) {
                try (InputStream data = entry.getData()) {
                    var out = new ByteArrayOutputStream();
                    data.transferTo(out);
                    return out.toByteArray();
                }
            }
        }
        throw new IllegalArgumentException("no entry named " + name);
    }

    /**
     * Unzips a TDF, applies the given edits to its manifest and payload, and zips it back
     * up. Everything here is available to an attacker who has the file and no key.
     */
    private static byte[] rewrite(byte[] tdfBytes, Consumer<JsonObject> editManifest,
            UnaryOperator<byte[]> editPayload) throws IOException {
        var manifest = JsonParser.parseString(manifestOf(tdfBytes)).getAsJsonObject();
        editManifest.accept(manifest);
        var payload = editPayload.apply(entry(tdfBytes, TDFWriter.TDF_PAYLOAD_FILE_NAME));

        var rewritten = new ByteArrayOutputStream();
        var writer = new TDFWriter(rewritten);
        try (var payloadOut = writer.payload()) {
            payloadOut.write(payload);
        }
        writer.appendManifest(new Gson().toJson(manifest));
        writer.finish();
        return rewritten.toByteArray();
    }
}
