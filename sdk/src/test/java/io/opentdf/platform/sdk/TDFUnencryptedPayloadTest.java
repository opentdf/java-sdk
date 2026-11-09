package io.opentdf.platform.sdk;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.KeyLengthException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.AdditionalAnswers;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;

/**
 * The reader only supports encrypted payloads. A manifest that does not declare one is refused
 * as malformed, before any key access, integrity or assertion processing.
 */
class TDFUnencryptedPayloadTest {

    private static final int SEGMENT_SIZE = Config.MIN_SEGMENT_SIZE;
    private static final String KAS_URL = "https://example.com/kas0";
    private static final String ASSERTION_ID = "assertion1";
    /** What the reader's payload key starts as before any split is folded in. */
    private static final byte[] ZERO_KEY = new byte[32];

    private static KeyPair kasKeyPair;

    private static final SDK.KAS FAKE_KAS = new SDK.KAS() {
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

    @Test
    void untouchedTdfLoads() throws IOException {
        // Positive control, for the TDF and for the KAS spy: the negative cases below
        // only mean something if this one unwraps through the spy and reads back.
        var plaintext = plaintext('A');
        var kas = kasSpy();

        var reader = load(createTdf(plaintext), kas);

        assertThat(readAll(reader)).containsExactly(plaintext);
        assertThat(reader.getManifest().payload.isEncrypted).isTrue();
        Mockito.verify(kas, Mockito.atLeastOnce()).unwrap(any(), any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = { "false", "absent", "null" })
    void manifestNotDeclaringAnEncryptedPayloadIsRejected(String flag) throws IOException {
        // Every other value in the manifest is consistent with a payload stored as-is, so
        // the flag is the only thing that can cause the rejection.
        var unencrypted = rewriteAsUnencrypted(createTdf(plaintext('A')), plaintext('Z'), flag);
        var kas = kasSpy();

        assertThatThrownBy(() -> load(unencrypted, kas))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("isEncrypted");
        Mockito.verifyNoInteractions(kas);
    }

    @Test
    void flippingTheFlagAloneIsRejectedAsMalformed() throws IOException {
        // Nothing else edited, so the rejection is the flag check itself and not a later
        // integrity failure.
        var tdf = createTdf(plaintext('A'));
        var manifest = JsonParser.parseString(manifestOf(tdf)).getAsJsonObject();
        manifest.getAsJsonObject("payload").addProperty("isEncrypted", false);
        var tampered = zip(manifest.toString(), entry(tdf, TDFWriter.TDF_PAYLOAD_FILE_NAME));
        var kas = kasSpy();

        assertThatThrownBy(() -> load(tampered, kas))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("isEncrypted");
        Mockito.verifyNoInteractions(kas);
    }

    // ----------------------------------------------------------------- fixtures

    private static byte[] plaintext(char fill) {
        var plaintext = new byte[2 * SEGMENT_SIZE + SEGMENT_SIZE / 2];
        Arrays.fill(plaintext, (byte) fill);
        return plaintext;
    }

    private static SDK.KAS kasSpy() {
        return Mockito.mock(SDK.KAS.class, AdditionalAnswers.delegatesTo(FAKE_KAS));
    }

    private static byte[] createTdf(byte[] plaintext) throws IOException {
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = KAS_URL;

        var assertionConfig = new AssertionConfig();
        assertionConfig.id = ASSERTION_ID;
        assertionConfig.type = AssertionConfig.Type.BaseAssertion;
        assertionConfig.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig.statement = new AssertionConfig.Statement();
        assertionConfig.statement.format = "base64binary";
        assertionConfig.statement.schema = "text";
        assertionConfig.statement.value = "ICAgIDxlZGoOkVkaD4=";

        var config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(kasInfo),
                Config.withSegmentSize(SEGMENT_SIZE),
                Config.withAssertionConfig(assertionConfig));

        var tdfBytes = new ByteArrayOutputStream();
        new TDF(new FakeServicesBuilder().setKas(FAKE_KAS).build())
                .createTDF(new ByteArrayInputStream(plaintext), tdfBytes, config);
        return tdfBytes.toByteArray();
    }

    /** Loads through the same entry point {@link SDK#loadTDF} uses, with an allowlist so no registry is consulted. */
    private static TDF.Reader load(byte[] tdfBytes, SDK.KAS kas) throws IOException {
        return new TDF(new FakeServicesBuilder().setKas(kas).build()).loadTDF(
                new SeekableInMemoryByteChannel(tdfBytes),
                Config.newTDFReaderConfig(Config.WithKasAllowlist(KAS_URL)),
                KAS_URL);
    }

    private static byte[] readAll(TDF.Reader reader) throws IOException {
        var out = new ByteArrayOutputStream();
        reader.readPayload(out);
        return out.toByteArray();
    }

    // ------------------------------------------------------- manifest surgery

    /**
     * Replaces the payload with {@code chosen}, stored as-is, recomputes the segment hashes,
     * root signature and assertion binding to be consistent with an unencrypted payload, and
     * sets {@code payload.isEncrypted} as {@code flag} says.
     */
    private static byte[] rewriteAsUnencrypted(byte[] tdfBytes, byte[] chosen, String flag) throws IOException {
        Manifest manifest = Manifest.readManifest(manifestOf(tdfBytes));
        var integrity = manifest.encryptionInformation.integrityInformation;

        var segments = new ArrayList<Manifest.Segment>();
        var aggregate = new ByteArrayOutputStream();
        for (int offset = 0; offset < chosen.length; offset += SEGMENT_SIZE) {
            var bytes = Arrays.copyOfRange(chosen, offset, Math.min(chosen.length, offset + SEGMENT_SIZE));
            var segment = new Manifest.Segment();
            segment.hash = Hex.encodeHexString(sha256(bytes));
            segment.segmentSize = bytes.length;
            segment.encryptedSegmentSize = bytes.length;
            segments.add(segment);
            aggregate.writeBytes(segment.hash.getBytes(StandardCharsets.US_ASCII));
        }
        integrity.segments = segments;
        integrity.rootSignature.signature = Base64.getEncoder().encodeToString(sha256(aggregate.toByteArray()));
        rebindAssertions(manifest, aggregate.toByteArray(), ZERO_KEY);

        var json = JsonParser.parseString(Manifest.toJson(manifest)).getAsJsonObject();
        setFlag(json.getAsJsonObject("payload"), flag);
        return zip(json.toString(), chosen);
    }

    private static void setFlag(JsonObject payload, String flag) {
        switch (flag) {
            case "false":
                payload.addProperty("isEncrypted", false);
                break;
            case "absent":
                payload.remove("isEncrypted");
                break;
            case "null":
                payload.add("isEncrypted", JsonNull.INSTANCE);
                break;
            default:
                throw new IllegalArgumentException(flag);
        }
    }

    /** Re-binds every assertion over {@code aggregate} with HS256 under {@code key}, as the writer would. */
    private static void rebindAssertions(Manifest manifest, byte[] aggregate, byte[] key) throws IOException {
        assertThat(manifest.assertions).extracting(a -> a.id).containsExactly(ASSERTION_ID);
        for (var assertion : manifest.assertions) {
            assertion.binding = null;
            var assertionHash = assertion.hash();
            byte[] assertionHashBytes;
            try {
                assertionHashBytes = Hex.decodeHex(assertionHash);
            } catch (org.apache.commons.codec.DecoderException e) {
                throw new IllegalStateException(e);
            }
            var signed = new byte[aggregate.length + assertionHashBytes.length];
            System.arraycopy(aggregate, 0, signed, 0, aggregate.length);
            System.arraycopy(assertionHashBytes, 0, signed, aggregate.length, assertionHashBytes.length);
            try {
                assertion.sign(
                        new Manifest.Assertion.HashValues(assertionHash, Base64.getEncoder().encodeToString(signed)),
                        new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key));
            } catch (KeyLengthException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
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

    private static byte[] zip(String manifestJson, byte[] payload) throws IOException {
        var rewritten = new ByteArrayOutputStream();
        var writer = new TDFWriter(rewritten);
        try (var payloadOut = writer.payload()) {
            payloadOut.write(payload);
        }
        writer.appendManifest(manifestJson);
        writer.finish();
        return rewritten.toByteArray();
    }
}
