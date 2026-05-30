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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JVM WASM host that loads a TinyGo-built TDF encrypt module via Chicory,
 * provides host crypto using Java SDK classes, and validates round-trip
 * encrypt/decrypt.
 */
public class WasmTdfTest {

    /** Thrown by our proc_exit override to halt _start without killing the module. */
    private static class ProcExitSignal extends RuntimeException {
        final int exitCode;
        ProcExitSignal(int code) { this.exitCode = code; }
    }

    private static final long ERR_SENTINEL = 0xFFFFFFFFL;
    private static final int ALG_HS256 = 0;
    private static final int ALG_GMAC = 1;

    private Instance instance;
    private String kasPubPEM;
    private String kasPrivPEM;
    private String lastError = "";

    // Streaming I/O state
    private byte[] pendingInput;
    private int inputOffset;
    private ByteArrayOutputStream outputBuffer;

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

            // Override proc_exit so the module stays alive after _start.
            // TinyGo/Go wasip1 calls proc_exit(0) after main() — we throw
            // ProcExitSignal to halt _start without closing the module.
            List<HostFunction> wasiFns = new ArrayList<>();
            for (HostFunction fn : wasi.toHostFunctions()) {
                if (!"proc_exit".equals(fn.name())) {
                    wasiFns.add(fn);
                }
            }
            wasiFns.add(new HostFunction(
                    "wasi_snapshot_preview1", "proc_exit",
                    FunctionType.of(List.of(ValType.I32), List.of()),
                    (inst, args) -> {
                        throw new ProcExitSignal((int) args[0]);
                    }));

            var store = new Store();
            store.addFunction(wasiFns.toArray(new HostFunction[0]));
            store.addFunction(cryptoHostFunctions());
            store.addFunction(ioHostFunctions());

            // Instantiate without auto-calling _start, then call it manually
            var module = Parser.parse(wasmStream);
            instance = store.instantiate("tdfcore", importValues ->
                    Instance.builder(module)
                            .withImportValues(importValues)
                            .withStart(false)
                            .build());
        }

        // Call _start to init runtime. proc_exit(0) is expected after main().
        try {
            instance.export("_start").apply();
        } catch (ProcExitSignal e) {
            if (e.exitCode != 0) throw new RuntimeException("WASM _start exited with code " + e.exitCode);
        }
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
                new HostFunction(
                        "io", "read_input",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> {
                            int bufPtr = (int) args[0];
                            int bufCapacity = (int) args[1];
                            if (pendingInput == null || inputOffset >= pendingInput.length) {
                                return new long[]{0}; // EOF
                            }
                            int remaining = pendingInput.length - inputOffset;
                            int toRead = Math.min(bufCapacity, remaining);
                            inst.memory().write(bufPtr,
                                    Arrays.copyOfRange(pendingInput, inputOffset, inputOffset + toRead));
                            inputOffset += toRead;
                            return new long[]{toRead};
                        }),

                new HostFunction(
                        "io", "write_output",
                        FunctionType.of(List.of(ValType.I32, ValType.I32), List.of(ValType.I32)),
                        (inst, args) -> {
                            int bufPtr = (int) args[0];
                            int bufLen = (int) args[1];
                            byte[] data = inst.memory().readBytes(bufPtr, bufLen);
                            outputBuffer.write(data, 0, bufLen);
                            return new long[]{bufLen};
                        })
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
        return wasmEncryptWithSegSize(plaintext, integrityAlg, segIntegrityAlg, 0);
    }

    private byte[] wasmEncryptWithSegSize(byte[] plaintext, int integrityAlg, int segIntegrityAlg, int segmentSize) {
        byte[] kasPubBytes = kasPubPEM.getBytes(StandardCharsets.UTF_8);
        byte[] kasURLBytes = "https://kas.example.com".getBytes(StandardCharsets.UTF_8);
        byte[] attrBytes = "https://example.com/attr/classification/value/secret"
                .getBytes(StandardCharsets.UTF_8);

        long kasPubPtr = allocAndWrite(kasPubBytes);
        long kasURLPtr = allocAndWrite(kasURLBytes);
        long attrPtr = allocAndWrite(attrBytes);

        // Set up streaming I/O state
        pendingInput = plaintext;
        inputOffset = 0;
        outputBuffer = new ByteArrayOutputStream(plaintext.length + 65536);

        long[] result = instance.export("tdf_encrypt").apply(
                kasPubPtr, (long) kasPubBytes.length,
                kasURLPtr, (long) kasURLBytes.length,
                attrPtr, (long) attrBytes.length,
                (long) plaintext.length, // plaintextSize (i64)
                (long) integrityAlg, (long) segIntegrityAlg,
                (long) segmentSize
        );

        long resultLen = result[0];
        assertTrue(resultLen > 0, "WASM encrypt failed: " + getWasmError());

        byte[] output = outputBuffer.toByteArray();
        assertEquals(resultLen, output.length, "Output length mismatch");
        return output;
    }

    private Map<String, byte[]> parseZip(byte[] zipBytes) throws Exception {
        // Use ZipFile (central-directory based) instead of ZipInputStream to
        // handle data descriptors on STORED entries (multi-segment TDFs).
        File tmp = File.createTempFile("tdf-test-", ".zip");
        try {
            Files.write(tmp.toPath(), zipBytes);
            Map<String, byte[]> entries = new HashMap<>();
            try (ZipFile zf = new ZipFile(tmp)) {
                var it = zf.entries();
                while (it.hasMoreElements()) {
                    ZipEntry entry = it.nextElement();
                    try (InputStream is = zf.getInputStream(entry)) {
                        entries.put(entry.getName(), is.readAllBytes());
                    }
                }
            }
            return entries;
        } finally {
            tmp.delete();
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

        long kasPubPtr = allocAndWrite(invalidPEM);
        long kasURLPtr = allocAndWrite(kasURLBytes);
        long attrPtr = wasmMalloc(1); // empty attrs need at least 1 byte allocation

        // Set up streaming I/O state
        pendingInput = plaintext;
        inputOffset = 0;
        outputBuffer = new ByteArrayOutputStream();

        long[] result = instance.export("tdf_encrypt").apply(
                kasPubPtr, (long) invalidPEM.length,
                kasURLPtr, (long) kasURLBytes.length,
                attrPtr, 0L,
                (long) plaintext.length, // plaintextSize (i64)
                (long) ALG_HS256, (long) ALG_HS256,
                0L // default segment size
        );

        assertEquals(0, result[0], "Expected encrypt to fail with invalid PEM");

        String error = getWasmError();
        assertFalse(error.isEmpty(), "Expected non-empty error message");
    }

    @Test
    void testStreamingLargePayload() throws Exception {
        // 1MB payload with 64KB segments → 16 segments
        int payloadSize = 1024 * 1024;
        int segSize = 64 * 1024;
        byte[] plaintext = new byte[payloadSize];
        new SecureRandom().nextBytes(plaintext);

        byte[] tdfBytes = wasmEncryptWithSegSize(plaintext, ALG_HS256, ALG_HS256, segSize);

        // Parse ZIP and verify structure
        Map<String, byte[]> entries = parseZip(tdfBytes);
        assertTrue(entries.containsKey("0.manifest.json"), "Missing manifest");
        assertTrue(entries.containsKey("0.payload"), "Missing payload");

        // Verify segment count in manifest
        String manifestJson = new String(entries.get("0.manifest.json"), StandardCharsets.UTF_8);
        JsonObject manifest = JsonParser.parseString(manifestJson).getAsJsonObject();
        JsonObject encInfo = manifest.getAsJsonObject("encryptionInformation");
        JsonObject intInfo = encInfo.getAsJsonObject("integrityInformation");
        int segmentCount = intInfo.getAsJsonArray("segments").size();
        assertEquals(16, segmentCount, "Expected 16 segments for 1MB / 64KB");

        // Unwrap DEK and decrypt each segment to verify round-trip
        String wrappedKeyB64 = encInfo.getAsJsonArray("keyAccess")
                .get(0).getAsJsonObject().get("wrappedKey").getAsString();
        byte[] dek = new AsymDecryption(kasPrivPEM).decrypt(
                Base64.getDecoder().decode(wrappedKeyB64));

        // Decrypt all segments and reassemble plaintext
        byte[] payload = entries.get("0.payload");
        ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream(payloadSize);
        int offset = 0;
        for (int i = 0; i < segmentCount; i++) {
            long encSegSize = intInfo.getAsJsonArray("segments")
                    .get(i).getAsJsonObject().get("encryptedSegmentSize").getAsLong();
            byte[] segCt = Arrays.copyOfRange(payload, offset, offset + (int) encSegSize);
            byte[] segPt = new AesGcm(dek).decrypt(new AesGcm.Encrypted(segCt));
            decryptedOut.write(segPt);
            offset += (int) encSegSize;
        }

        assertArrayEquals(plaintext, decryptedOut.toByteArray(),
                "Decrypted plaintext must match original");
    }
}
