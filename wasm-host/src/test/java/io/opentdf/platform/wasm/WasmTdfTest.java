package io.opentdf.platform.wasm;

import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Store;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.types.FunctionType;
import com.dylibso.chicory.wasm.types.ValType;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.opentdf.platform.sdk.AesGcm;
import io.opentdf.platform.sdk.AsymDecryption;
import io.opentdf.platform.sdk.AsymEncryption;
import io.opentdf.platform.sdk.CryptoUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JVM WASM host that loads a TinyGo-built TDF encrypt module via Chicory,
 * provides host crypto using Java SDK classes, and validates round-trip
 * encrypt/decrypt.
 */
public class WasmTdfTest {

    private static final long ERR_SENTINEL = 0xFFFFFFFFL;
    private static final int ALG_HS256 = 0;
    private static final int ALG_GMAC = 1;

    private Instance instance;
    private String kasPubPEM;
    private String kasPrivPEM;
    private String lastError = "";

    @BeforeEach
    void setUp() throws Exception {
        KeyPair kp = CryptoUtils.generateRSAKeypair();
        kasPubPEM = CryptoUtils.getRSAPublicKeyPEM(kp.getPublic());
        kasPrivPEM = CryptoUtils.getRSAPrivateKeyPEM(kp.getPrivate());

        try (InputStream wasmStream = Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream("tdfcore.wasm"),
                "tdfcore.wasm not found in test resources")) {

            var wasi = WasiPreview1.builder()
                    .withOptions(WasiOptions.builder().build())
                    .build();

            var store = new Store();
            store.addFunction(wasi.toHostFunctions());
            store.addFunction(cryptoHostFunctions());
            store.addFunction(ioHostFunctions());

            instance = store.instantiate("tdfcore", Parser.parse(wasmStream));
        }

        // Initialize the TinyGo c-shared module
        instance.export("_initialize").apply();
    }

    // ---- Host crypto functions ----

    private HostFunction[] cryptoHostFunctions() {
        return new HostFunction[]{
                new HostFunction(
                        "crypto", "random_bytes",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> {
                            int outPtr = (int) args[0];
                            int n = (int) args[1];
                            byte[] bytes = new byte[n];
                            new SecureRandom().nextBytes(bytes);
                            inst.memory().write(outPtr, bytes);
                            return new long[]{n};
                        }),

                new HostFunction(
                        "crypto", "aes_gcm_encrypt",
                        FunctionType.of(
                                List.of(ValType.I32, ValType.I32, ValType.I32, ValType.I32, ValType.I32),
                                List.of(ValType.I32)),
                        (inst, args) -> {
                            try {
                                byte[] key = inst.memory().readBytes((int) args[0], (int) args[1]);
                                byte[] pt = inst.memory().readBytes((int) args[2], (int) args[3]);
                                AesGcm.Encrypted encrypted = new AesGcm(key).encrypt(pt);
                                byte[] result = encrypted.asBytes();
                                inst.memory().write((int) args[4], result);
                                return new long[]{result.length};
                            } catch (Exception e) {
                                lastError = e.getMessage();
                                return new long[]{ERR_SENTINEL};
                            }
                        }),

                new HostFunction(
                        "crypto", "aes_gcm_decrypt",
                        FunctionType.of(
                                List.of(ValType.I32, ValType.I32, ValType.I32, ValType.I32, ValType.I32),
                                List.of(ValType.I32)),
                        (inst, args) -> {
                            try {
                                byte[] key = inst.memory().readBytes((int) args[0], (int) args[1]);
                                byte[] ct = inst.memory().readBytes((int) args[2], (int) args[3]);
                                byte[] decrypted = new AesGcm(key).decrypt(new AesGcm.Encrypted(ct));
                                inst.memory().write((int) args[4], decrypted);
                                return new long[]{decrypted.length};
                            } catch (Exception e) {
                                lastError = e.getMessage();
                                return new long[]{ERR_SENTINEL};
                            }
                        }),

                new HostFunction(
                        "crypto", "hmac_sha256",
                        FunctionType.of(
                                List.of(ValType.I32, ValType.I32, ValType.I32, ValType.I32, ValType.I32),
                                List.of(ValType.I32)),
                        (inst, args) -> {
                            try {
                                byte[] key = inst.memory().readBytes((int) args[0], (int) args[1]);
                                byte[] data = inst.memory().readBytes((int) args[2], (int) args[3]);
                                byte[] hmac = CryptoUtils.CalculateSHA256Hmac(key, data);
                                inst.memory().write((int) args[4], hmac);
                                return new long[]{hmac.length};
                            } catch (Exception e) {
                                lastError = e.getMessage();
                                return new long[]{ERR_SENTINEL};
                            }
                        }),

                new HostFunction(
                        "crypto", "rsa_oaep_sha1_encrypt",
                        FunctionType.of(
                                List.of(ValType.I32, ValType.I32, ValType.I32, ValType.I32, ValType.I32),
                                List.of(ValType.I32)),
                        (inst, args) -> {
                            try {
                                String pubPEM = inst.memory().readString((int) args[0], (int) args[1]);
                                byte[] pt = inst.memory().readBytes((int) args[2], (int) args[3]);
                                byte[] encrypted = new AsymEncryption(pubPEM).encrypt(pt);
                                inst.memory().write((int) args[4], encrypted);
                                return new long[]{encrypted.length};
                            } catch (Exception e) {
                                lastError = e.getMessage();
                                return new long[]{ERR_SENTINEL};
                            }
                        }),

                new HostFunction(
                        "crypto", "rsa_oaep_sha1_decrypt",
                        FunctionType.of(
                                List.of(ValType.I32, ValType.I32, ValType.I32, ValType.I32, ValType.I32),
                                List.of(ValType.I32)),
                        (inst, args) -> {
                            try {
                                String privPEM = inst.memory().readString((int) args[0], (int) args[1]);
                                byte[] ct = inst.memory().readBytes((int) args[2], (int) args[3]);
                                byte[] decrypted = new AsymDecryption(privPEM).decrypt(ct);
                                inst.memory().write((int) args[4], decrypted);
                                return new long[]{decrypted.length};
                            } catch (Exception e) {
                                lastError = e.getMessage();
                                return new long[]{ERR_SENTINEL};
                            }
                        }),

                new HostFunction(
                        "crypto", "rsa_generate_keypair",
                        FunctionType.of(
                                List.of(ValType.I32, ValType.I32, ValType.I32, ValType.I32),
                                List.of(ValType.I32)),
                        (inst, args) -> {
                            try {
                                // args[0] = bits (unused, always 2048)
                                KeyPair kp = CryptoUtils.generateRSAKeypair();
                                byte[] privPEM = CryptoUtils.getRSAPrivateKeyPEM(kp.getPrivate())
                                        .getBytes(StandardCharsets.UTF_8);
                                byte[] pubPEM = CryptoUtils.getRSAPublicKeyPEM(kp.getPublic())
                                        .getBytes(StandardCharsets.UTF_8);
                                inst.memory().write((int) args[1], privPEM);
                                inst.memory().write((int) args[2], pubPEM);
                                inst.memory().writeI32((int) args[3], pubPEM.length);
                                return new long[]{privPEM.length};
                            } catch (Exception e) {
                                lastError = e.getMessage();
                                return new long[]{ERR_SENTINEL};
                            }
                        }),

                new HostFunction(
                        "crypto", "get_last_error",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> {
                            if (lastError.isEmpty()) {
                                return new long[]{0};
                            }
                            byte[] errBytes = lastError.getBytes(StandardCharsets.UTF_8);
                            int cap = (int) args[1];
                            int len = Math.min(errBytes.length, cap);
                            inst.memory().write((int) args[0], Arrays.copyOf(errBytes, len));
                            lastError = "";
                            return new long[]{len};
                        })
        };
    }

    private HostFunction[] ioHostFunctions() {
        return new HostFunction[]{
                // read_input: return 0 (EOF) — not used during encrypt
                new HostFunction(
                        "io", "read_input",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> new long[]{0}),

                // write_output: no-op, return length — not used during encrypt
                new HostFunction(
                        "io", "write_output",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> new long[]{args[1]})
        };
    }

    // ---- Helpers ----

    private long wasmMalloc(int size) {
        long[] result = instance.export("tdf_malloc").apply((long) size);
        return result[0];
    }

    private long allocAndWrite(byte[] data) {
        long ptr = wasmMalloc(data.length);
        instance.memory().write((int) ptr, data);
        return ptr;
    }

    private String getWasmError() {
        long errBufPtr = wasmMalloc(4096);
        long[] result = instance.export("get_error").apply(errBufPtr, 4096L);
        int errLen = (int) result[0];
        if (errLen == 0) {
            return "";
        }
        return instance.memory().readString((int) errBufPtr, errLen);
    }

    private byte[] wasmEncrypt(byte[] plaintext, int integrityAlg, int segIntegrityAlg) {
        byte[] kasPubBytes = kasPubPEM.getBytes(StandardCharsets.UTF_8);
        byte[] kasURLBytes = "https://kas.example.com".getBytes(StandardCharsets.UTF_8);
        byte[] attrBytes = "https://example.com/attr/classification/value/secret"
                .getBytes(StandardCharsets.UTF_8);

        long kasPubPtr = allocAndWrite(kasPubBytes);
        long kasURLPtr = allocAndWrite(kasURLBytes);
        long attrPtr = allocAndWrite(attrBytes);
        long ptPtr = allocAndWrite(plaintext);

        int outCapacity = 1024 * 1024;
        long outPtr = wasmMalloc(outCapacity);

        long[] result = instance.export("tdf_encrypt").apply(
                kasPubPtr, (long) kasPubBytes.length,
                kasURLPtr, (long) kasURLBytes.length,
                attrPtr, (long) attrBytes.length,
                ptPtr, (long) plaintext.length,
                outPtr, (long) outCapacity,
                (long) integrityAlg, (long) segIntegrityAlg
        );

        long resultLen = result[0];
        assertTrue(resultLen > 0, "WASM encrypt failed: " + getWasmError());

        return instance.memory().readBytes((int) outPtr, (int) resultLen);
    }

    private Map<String, byte[]> parseZip(byte[] zipBytes) throws Exception {
        // Use ZipFile (central-directory based) instead of ZipInputStream because
        // the TDF ZIP uses STORED entries with data descriptors, which ZipInputStream rejects.
        Path tempFile = Files.createTempFile("tdf", ".zip");
        try {
            Files.write(tempFile, zipBytes);
            Map<String, byte[]> entries = new HashMap<>();
            try (ZipFile zf = new ZipFile(tempFile.toFile())) {
                Enumeration<? extends ZipEntry> e = zf.entries();
                while (e.hasMoreElements()) {
                    ZipEntry entry = e.nextElement();
                    try (InputStream is = zf.getInputStream(entry)) {
                        entries.put(entry.getName(), is.readAllBytes());
                    }
                }
            }
            return entries;
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    // ---- Tests ----

    @Test
    void testHS256RoundTrip() throws Exception {
        byte[] plaintext = "Hello, TDF from JVM WASM host!".getBytes(StandardCharsets.UTF_8);
        byte[] tdfBytes = wasmEncrypt(plaintext, ALG_HS256, ALG_HS256);

        // Parse ZIP
        Map<String, byte[]> entries = parseZip(tdfBytes);
        assertTrue(entries.containsKey("0.manifest.json"), "Missing manifest");
        assertTrue(entries.containsKey("0.payload"), "Missing payload");

        // Parse manifest
        String manifestJson = new String(entries.get("0.manifest.json"), StandardCharsets.UTF_8);
        JsonObject manifest = JsonParser.parseString(manifestJson).getAsJsonObject();

        // Verify manifest structure
        assertEquals("4.3.0", manifest.get("schemaVersion").getAsString());

        JsonObject encInfo = manifest.getAsJsonObject("encryptionInformation");
        assertEquals("AES-256-GCM",
                encInfo.getAsJsonObject("method").get("algorithm").getAsString());

        JsonObject intInfo = encInfo.getAsJsonObject("integrityInformation");
        assertEquals("HS256", intInfo.getAsJsonObject("rootSignature").get("alg").getAsString());
        assertEquals("HS256", intInfo.get("segmentHashAlg").getAsString());

        // Unwrap DEK with our private key
        String wrappedKeyB64 = encInfo.getAsJsonArray("keyAccess")
                .get(0).getAsJsonObject().get("wrappedKey").getAsString();
        byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64);
        byte[] dek = new AsymDecryption(kasPrivPEM).decrypt(wrappedKey);

        // Decrypt payload: [iv(12) || ciphertext || tag(16)]
        byte[] payload = entries.get("0.payload");
        byte[] decrypted = new AesGcm(dek).decrypt(new AesGcm.Encrypted(payload));

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testGMACRoundTrip() throws Exception {
        byte[] plaintext = "GMAC integrity test from JVM".getBytes(StandardCharsets.UTF_8);
        byte[] tdfBytes = wasmEncrypt(plaintext, ALG_HS256, ALG_GMAC);

        Map<String, byte[]> entries = parseZip(tdfBytes);
        String manifestJson = new String(entries.get("0.manifest.json"), StandardCharsets.UTF_8);
        JsonObject manifest = JsonParser.parseString(manifestJson).getAsJsonObject();

        JsonObject encInfo = manifest.getAsJsonObject("encryptionInformation");
        JsonObject intInfo = encInfo.getAsJsonObject("integrityInformation");
        assertEquals("GMAC", intInfo.get("segmentHashAlg").getAsString());

        // GMAC = last 16 bytes of ciphertext (the GCM auth tag)
        byte[] payload = entries.get("0.payload");
        byte[] cipher = Arrays.copyOfRange(payload, 12, payload.length);
        byte[] gmacTag = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        String expectedSegHash = Base64.getEncoder().encodeToString(gmacTag);

        String actualSegHash = intInfo.getAsJsonArray("segments")
                .get(0).getAsJsonObject().get("hash").getAsString();
        assertEquals(expectedSegHash, actualSegHash);

        // Decrypt and verify round-trip
        String wrappedKeyB64 = encInfo.getAsJsonArray("keyAccess")
                .get(0).getAsJsonObject().get("wrappedKey").getAsString();
        byte[] dek = new AsymDecryption(kasPrivPEM).decrypt(
                Base64.getDecoder().decode(wrappedKeyB64));
        byte[] decrypted = new AesGcm(dek).decrypt(new AesGcm.Encrypted(payload));

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testErrorHandlingInvalidPEM() {
        byte[] plaintext = "test".getBytes(StandardCharsets.UTF_8);
        byte[] invalidPEM = "not-a-valid-pem".getBytes(StandardCharsets.UTF_8);
        byte[] kasURLBytes = "https://kas.example.com".getBytes(StandardCharsets.UTF_8);
        byte[] attrBytes = new byte[0];

        long kasPubPtr = allocAndWrite(invalidPEM);
        long kasURLPtr = allocAndWrite(kasURLBytes);
        long attrPtr = wasmMalloc(1); // empty attrs need at least 1 byte allocation
        long ptPtr = allocAndWrite(plaintext);

        int outCapacity = 1024 * 1024;
        long outPtr = wasmMalloc(outCapacity);

        long[] result = instance.export("tdf_encrypt").apply(
                kasPubPtr, (long) invalidPEM.length,
                kasURLPtr, (long) kasURLBytes.length,
                attrPtr, 0L,
                ptPtr, (long) plaintext.length,
                outPtr, (long) outCapacity,
                (long) ALG_HS256, (long) ALG_HS256
        );

        assertEquals(0, result[0], "Expected encrypt to fail with invalid PEM");

        String error = getWasmError();
        assertFalse(error.isEmpty(), "Expected non-empty error message");
    }
}
