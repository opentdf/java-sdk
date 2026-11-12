package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The payload key is built only from key access objects. A manifest without any is refused as
 * malformed when the TDF is loaded, before any KAS, integrity or assertion step.
 */
class TDFKeyAccessTest {

    private static final String KAS_URL = "https://example.com/kas0";
    private static final byte[] PLAINTEXT = "key access objects".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ZERO_KEY = new byte[32];

    private static KeyPair kasKeyPair;
    private static final AtomicInteger unwraps = new AtomicInteger();

    private static final SDK.KAS KAS = new SDK.KAS() {
        @Override
        public void close() {
            // nothing to release
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
            unwraps.incrementAndGet();
            return new AsymDecryption(kasKeyPair.getPrivate()).decrypt(Base64.getDecoder().decode(keyAccess.wrappedKey));
        }

        @Override
        public KASKeyCache getKeyCache() {
            return new KASKeyCache();
        }
    };

    @BeforeAll
    static void generateKasKey() {
        kasKeyPair = CryptoUtils.generateRSAKeypair();
    }

    private static TDF tdf() {
        return new TDF(new FakeServicesBuilder().setKas(KAS).build());
    }

    private static byte[] createTdf() throws IOException {
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = KAS_URL;
        var out = new ByteArrayOutputStream();
        tdf().createTDF(new ByteArrayInputStream(PLAINTEXT), out,
                Config.newTDFConfig(Config.withAutoconfigure(false), Config.withKasInformation(kasInfo)));
        return out.toByteArray();
    }

    private static TDF.Reader load(byte[] tdfBytes) throws IOException {
        return tdf().loadTDF(new SeekableInMemoryByteChannel(tdfBytes),
                Config.newTDFReaderConfig(Config.WithIgnoreKasAllowlist(true)));
    }

    private static byte[] entry(byte[] tdfBytes, String name) throws IOException {
        for (var entry : new ZipReader(new SeekableInMemoryByteChannel(tdfBytes)).getEntries()) {
            if (entry.getName().equals(name)) {
                try (InputStream data = entry.getData()) {
                    return data.readAllBytes();
                }
            }
        }
        throw new IllegalArgumentException("no entry named " + name);
    }

    private static byte[] zip(JsonObject manifest, byte[] payload) throws IOException {
        var out = new ByteArrayOutputStream();
        var writer = new TDFWriter(out);
        try (var payloadOut = writer.payload()) {
            payloadOut.write(payload);
        }
        try (var manifestOut = writer.manifest()) {
            manifestOut.write(new Gson().toJson(manifest).getBytes(StandardCharsets.UTF_8));
        }
        writer.finish();
        return out.toByteArray();
    }

    /**
     * The TDF with its manifest edited by {@code edit}, and its payload, segment hash and root
     * signature redone under the all-zero key, the value the payload key starts from before any
     * split is folded in. Only the missing key access objects make it unreadable.
     */
    private static byte[] underTheZeroKey(byte[] tdfBytes, Consumer<JsonObject> edit) throws IOException {
        var manifest = JsonParser.parseString(new String(entry(tdfBytes, TDFWriter.TDF_MANIFEST_FILE_NAME),
                StandardCharsets.UTF_8)).getAsJsonObject();
        var integrity = manifest.getAsJsonObject("encryptionInformation").getAsJsonObject("integrityInformation");
        assertThat(integrity.get("segmentHashAlg").getAsString()).isEqualTo("GMAC");
        JsonArray segments = integrity.getAsJsonArray("segments");
        assertThat(segments).hasSize(1);

        byte[] encrypted = new AesGcm(ZERO_KEY).encrypt(PLAINTEXT, 0, PLAINTEXT.length).asBytes();
        byte[] tag = Arrays.copyOfRange(encrypted, encrypted.length - AesGcm.GCM_TAG_LENGTH, encrypted.length);
        segments.get(0).getAsJsonObject().addProperty("hash", Base64.getEncoder().encodeToString(tag));
        integrity.getAsJsonObject("rootSignature").addProperty("sig",
                Base64.getEncoder().encodeToString(CryptoUtils.CalculateSHA256Hmac(ZERO_KEY, tag)));
        edit.accept(manifest);
        return zip(manifest, encrypted);
    }

    @Test
    void aTdfWithKeyAccessObjectsLoads() throws IOException {
        unwraps.set(0);
        var reader = load(createTdf());
        var out = new ByteArrayOutputStream();
        reader.readPayload(out);
        assertThat(out.toByteArray()).isEqualTo(PLAINTEXT);
        assertThat(unwraps).hasValue(1);
    }

    @Test
    void anEmptyKeyAccessListIsMalformed() throws IOException {
        var withoutKeyAccess = underTheZeroKey(createTdf(), manifest ->
                manifest.getAsJsonObject("encryptionInformation").add("keyAccess", new JsonArray()));
        unwraps.set(0);
        assertThatThrownBy(() -> load(withoutKeyAccess))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("no key access objects");
        assertThat(unwraps).hasValue(0);
    }

    @Test
    void anAbsentKeyAccessListIsMalformed() throws IOException {
        var withoutKeyAccess = underTheZeroKey(createTdf(), manifest ->
                manifest.getAsJsonObject("encryptionInformation").remove("keyAccess"));
        unwraps.set(0);
        assertThatThrownBy(() -> load(withoutKeyAccess))
                .isInstanceOf(SDK.MalformedTDFException.class)
                .hasMessageContaining("no key access objects");
        assertThat(unwraps).hasValue(0);
    }
}
