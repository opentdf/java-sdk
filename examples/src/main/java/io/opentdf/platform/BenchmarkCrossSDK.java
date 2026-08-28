package io.opentdf.platform;

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
import io.opentdf.platform.sdk.*;
import org.apache.commons.cli.*;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.nio.file.Files;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class BenchmarkCrossSDK {

    /** Thrown by our proc_exit override to halt _start without killing the module. */
    private static class ProcExitSignal extends RuntimeException {
        final int exitCode;
        ProcExitSignal(int code) { this.exitCode = code; }
    }

    private static final long ERR_SENTINEL = 0xFFFFFFFFL;

    // WASM state
    private static Instance wasmInstance;
    private static String lastError = "";
    private static boolean wasmOK = false;
    private static String wasmBinaryPath;

    // RSA key pair for WASM encrypt/decrypt
    private static String wasmPubPEM;
    private static String wasmPrivPEM;

    // Streaming I/O state
    private static byte[] pendingInput;
    private static int inputOffset;
    private static ByteArrayOutputStream outputBuffer;

    public static void main(String[] args) throws Exception {
        Options options = new Options();
        options.addOption(Option.builder("i")
                .longOpt("iterations")
                .hasArg()
                .desc("Iterations per payload size to average (default: 5)")
                .build());
        options.addOption(Option.builder("s")
                .longOpt("sizes")
                .hasArg()
                .desc("Comma-separated payload sizes in bytes (default: 256,1024,16384,65536,262144,1048576)")
                .build());
        options.addOption(Option.builder("e")
                .longOpt("platform-endpoint")
                .hasArg()
                .desc("Platform endpoint (default: localhost:8080)")
                .build());
        options.addOption(Option.builder()
                .longOpt("client-id")
                .hasArg()
                .desc("OAuth client ID (default: opentdf)")
                .build());
        options.addOption(Option.builder()
                .longOpt("client-secret")
                .hasArg()
                .desc("OAuth client secret (default: secret)")
                .build());
        options.addOption(Option.builder("a")
                .longOpt("attribute")
                .hasArg()
                .desc("Data attribute (default: https://example.com/attr/attr1/value/value1)")
                .build());
        options.addOption(Option.builder("w")
                .longOpt("wasm-binary")
                .hasArg()
                .desc("Path to tdfcore.wasm (default: wasm-host/src/test/resources/tdfcore.wasm)")
                .build());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        int iterations = Integer.parseInt(cmd.getOptionValue("iterations", "5"));
        String sizesStr = cmd.getOptionValue("sizes", "256,1024,16384,65536,262144,1048576,10485760,104857600");
        String platformEndpoint = cmd.getOptionValue("platform-endpoint", "localhost:8080");
        String clientId = cmd.getOptionValue("client-id", "opentdf-sdk");
        String clientSecret = cmd.getOptionValue("client-secret", "secret");
        String attribute = cmd.getOptionValue("attribute", "https://example.com/attr/attr1/value/value1");
        wasmBinaryPath = cmd.getOptionValue("wasm-binary", "wasm-host/src/test/resources/tdfcore.wasm");

        int[] sizes = parseSizes(sizesStr);

        // Setup SDK
        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret)
                .useInsecurePlaintextConnection(true)
                .build();

        String kasUrl = "http://" + platformEndpoint + "/kas";

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = kasUrl;

        SecureRandom random = new SecureRandom();

        // Setup WASM runtime + RSA keypair
        System.out.println("Initializing WASM runtime (Chicory)...");
        KeyPair kp = CryptoUtils.generateRSAKeypair();
        wasmPubPEM = CryptoUtils.getRSAPublicKeyPEM(kp.getPublic());
        wasmPrivPEM = CryptoUtils.getRSAPrivateKeyPEM(kp.getPrivate());
        try {
            initWasm(wasmBinaryPath);
            wasmOK = true;
            System.out.println("WASM runtime initialized.");
        } catch (Exception e) {
            System.out.println("WASM init failed: " + e.getMessage());
            wasmOK = false;
        }

        long[] encryptTimes = new long[sizes.length];
        long[] decryptTimes = new long[sizes.length];
        long[] wasmEncryptTimes = new long[sizes.length];
        long[] wasmDecryptTimes = new long[sizes.length];
        String[] wasmEncErrors = new String[sizes.length];
        String[] wasmDecErrors = new String[sizes.length];
        String[] sdkDecErrors = new String[sizes.length];

        for (int i = 0; i < sizes.length; i++) {
            int size = sizes[i];
            byte[] payload = new byte[size];
            random.nextBytes(payload);

            System.out.printf("Benchmarking %s ...%n", formatSize(size));

            // ── Native SDK encrypt ──────────────────────────────────
            byte[] lastTdf = null;
            long encTotal = 0;
            for (int j = 0; j < iterations; j++) {
                var tdfConfig = Config.newTDFConfig(
                        Config.withKasInformation(kasInfo),
                        Config.withDataAttributes(attribute),
                        Config.withAutoconfigure(false));
                var in = new ByteArrayInputStream(payload);
                var out = new ByteArrayOutputStream();

                long start = System.nanoTime();
                sdk.createTDF(in, out, tdfConfig);
                encTotal += System.nanoTime() - start;

                lastTdf = out.toByteArray();
            }
            encryptTimes[i] = encTotal / iterations;

            // ── WASM encrypt ────────────────────────────────────────
            // Auto-select segment size: 0 for <1MB, 256KB for 1-10MB, 1MB for >10MB
            int segSize = 0;
            if (size > 10 * 1024 * 1024) {
                segSize = 1024 * 1024;
            } else if (size >= 1024 * 1024) {
                segSize = 256 * 1024;
            }

            byte[] wasmTdf = null;
            if (wasmOK) {
                try {
                    long wasmEncTotal = 0;
                    for (int j = 0; j < iterations; j++) {
                        long start = System.nanoTime();
                        byte[] tdf = wasmEncryptWithSegSize(payload, wasmPubPEM, segSize);
                        wasmEncTotal += System.nanoTime() - start;
                        wasmTdf = tdf;
                    }
                    wasmEncryptTimes[i] = wasmEncTotal / iterations;
                } catch (Exception e) {
                    System.out.printf("  WASM encrypt failed: %s%n", e.getMessage());
                    wasmEncErrors[i] = "OOM";
                    reinitWasm();
                }
            } else {
                wasmEncErrors[i] = "N/A";
            }

            // ── Native SDK decrypt ──────────────────────────────────
            long decTotal = 0;
            try {
                for (int j = 0; j < iterations; j++) {
                    var channel = new SeekableInMemoryByteChannel(lastTdf);
                    var readerConfig = Config.newTDFReaderConfig();
                    var decOut = new ByteArrayOutputStream();

                    long start = System.nanoTime();
                    var reader = sdk.loadTDF(channel, readerConfig);
                    reader.readPayload(decOut);
                    decTotal += System.nanoTime() - start;
                }
                decryptTimes[i] = decTotal / iterations;
            } catch (Exception e) {
                System.out.printf("  SDK decrypt failed: %s%n", e.getMessage());
                sdkDecErrors[i] = "err";
            }

            // ── WASM decrypt ────────────────────────────────────────
            if (wasmTdf != null && wasmOK) {
                try {
                    long wasmDecTotal = 0;
                    for (int j = 0; j < iterations; j++) {
                        long start = System.nanoTime();
                        byte[] dek = unwrapDEKLocal(wasmTdf, wasmPrivPEM);
                        wasmDecrypt(wasmTdf, dek);
                        wasmDecTotal += System.nanoTime() - start;
                    }
                    // Add estimated KAS rewrap latency (25ms) for apples-to-apples comparison
                    wasmDecryptTimes[i] = wasmDecTotal / iterations + 25_000_000L;
                } catch (Exception e) {
                    System.out.printf("  WASM decrypt failed: %s%n", e.getMessage());
                    wasmDecErrors[i] = "OOM";
                    reinitWasm();
                }
            } else if (wasmEncErrors[i] != null) {
                wasmDecErrors[i] = "N/A";
            } else if (!wasmOK) {
                wasmDecErrors[i] = "N/A";
            }
        }

        // Print results
        System.out.println();
        System.out.println("# Cross-SDK Benchmark Results");
        System.out.printf("Platform: %s%n", platformEndpoint);
        System.out.printf("Iterations: %d per size%n", iterations);
        System.out.println();

        System.out.println("## Encrypt");
        System.out.println("| Payload | Java SDK | WASM |");
        System.out.println("|---------|----------|------|");
        for (int i = 0; i < sizes.length; i++) {
            String wasmCol = wasmEncErrors[i] != null ? wasmEncErrors[i] : fmtDurationMS(wasmEncryptTimes[i]);
            System.out.printf("| %s | %s | %s |%n", formatSize(sizes[i]), fmtDurationMS(encryptTimes[i]), wasmCol);
        }

        System.out.println();
        System.out.println("## Decrypt");
        System.out.println("| Payload | Java SDK* | WASM** |");
        System.out.println("|---------|-----------|--------|");
        for (int i = 0; i < sizes.length; i++) {
            String sdkCol = sdkDecErrors[i] != null ? sdkDecErrors[i] : fmtDurationMS(decryptTimes[i]);
            String wasmCol = wasmDecErrors[i] != null ? wasmDecErrors[i] : fmtDurationMS(wasmDecryptTimes[i]);
            System.out.printf("| %s | %s | %s |%n", formatSize(sizes[i]), sdkCol, wasmCol);
        }
        System.out.println("*Java SDK: includes KAS rewrap network latency");
        System.out.println("**WASM: local decrypt + estimated 25ms KAS rewrap latency");
    }

    // ── WASM lifecycle ──────────────────────────────────────────────────

    static void initWasm(String path) throws Exception {
        lastError = "";
        try (InputStream wasmStream = new FileInputStream(path)) {
            var wasi = WasiPreview1.builder()
                    .withOptions(WasiOptions.builder().build())
                    .build();

            // Override proc_exit so the module stays alive after _start.
            java.util.ArrayList<HostFunction> wasiFns = new java.util.ArrayList<>();
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

            var module = Parser.parse(wasmStream);
            wasmInstance = store.instantiate("tdfcore", importValues ->
                    Instance.builder(module)
                            .withImportValues(importValues)
                            .withStart(false)
                            .build());
        }

        // Call _start to init Go runtime. proc_exit(0) is expected.
        try {
            wasmInstance.export("_start").apply();
        } catch (ProcExitSignal e) {
            if (e.exitCode != 0) throw new RuntimeException("WASM _start exited with code " + e.exitCode);
        }
    }

    static void reinitWasm() {
        wasmInstance = null;
        try {
            initWasm(wasmBinaryPath);
            wasmOK = true;
        } catch (Exception e) {
            System.out.printf("  WASM runtime reinit failed: %s%n", e.getMessage());
            wasmOK = false;
        }
    }

    // ── Host crypto functions ───────────────────────────────────────────

    static HostFunction[] cryptoHostFunctions() {
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
                                KeyPair kpGen = CryptoUtils.generateRSAKeypair();
                                byte[] privPEM = CryptoUtils.getRSAPrivateKeyPEM(kpGen.getPrivate())
                                        .getBytes(StandardCharsets.UTF_8);
                                byte[] pubPEM = CryptoUtils.getRSAPublicKeyPEM(kpGen.getPublic())
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

    static HostFunction[] ioHostFunctions() {
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

    // ── WASM memory helpers ─────────────────────────────────────────────

    static long wasmMalloc(int size) {
        long[] result = wasmInstance.export("tdf_malloc").apply((long) size);
        return result[0];
    }

    static long allocAndWrite(byte[] data) {
        long ptr = wasmMalloc(data.length);
        wasmInstance.memory().write((int) ptr, data);
        return ptr;
    }

    static String getWasmError() {
        long errBufPtr = wasmMalloc(4096);
        long[] result = wasmInstance.export("get_error").apply(errBufPtr, 4096L);
        int errLen = (int) result[0];
        if (errLen == 0) {
            return "";
        }
        return wasmInstance.memory().readString((int) errBufPtr, errLen);
    }

    // ── WASM encrypt ────────────────────────────────────────────────────

    static byte[] wasmEncrypt(byte[] plaintext, String kasPubPEM) throws Exception {
        return wasmEncryptWithSegSize(plaintext, kasPubPEM, 0);
    }

    static byte[] wasmEncryptWithSegSize(byte[] plaintext, String kasPubPEM, int segmentSize) throws Exception {
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

        long[] result = wasmInstance.export("tdf_encrypt").apply(
                kasPubPtr, (long) kasPubBytes.length,
                kasURLPtr, (long) kasURLBytes.length,
                attrPtr, (long) attrBytes.length,
                (long) plaintext.length, // plaintextSize (i64)
                0L, 0L, // HS256 for root + segment integrity
                (long) segmentSize
        );

        long resultLen = result[0];
        if (resultLen == 0) {
            String err = getWasmError();
            throw new Exception("WASM encrypt failed: " + (err.isEmpty() ? "unknown error" : err));
        }

        return outputBuffer.toByteArray();
    }

    // ── DEK unwrap ──────────────────────────────────────────────────────

    static byte[] unwrapDEKLocal(byte[] tdfBytes, String privPEM) throws Exception {
        String manifestJson = null;
        File tmp = File.createTempFile("tdf-bench-", ".zip");
        try {
            Files.write(tmp.toPath(), tdfBytes);
            try (ZipFile zf = new ZipFile(tmp)) {
                ZipEntry entry = zf.getEntry("0.manifest.json");
                if (entry != null) {
                    try (InputStream is = zf.getInputStream(entry)) {
                        manifestJson = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                    }
                }
            }
        } finally {
            tmp.delete();
        }
        if (manifestJson == null) {
            throw new Exception("0.manifest.json not found in TDF ZIP");
        }

        JsonObject manifest = JsonParser.parseString(manifestJson).getAsJsonObject();
        JsonObject encInfo = manifest.getAsJsonObject("encryptionInformation");
        String wrappedKeyB64 = encInfo.getAsJsonArray("keyAccess")
                .get(0).getAsJsonObject().get("wrappedKey").getAsString();
        byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64);
        byte[] dek = new AsymDecryption(privPEM).decrypt(wrappedKey);
        if (dek.length != 32) {
            throw new Exception("DEK length: got " + dek.length + ", want 32");
        }
        return dek;
    }

    // ── WASM decrypt ────────────────────────────────────────────────────

    static byte[] wasmDecrypt(byte[] tdfBytes, byte[] dek) throws Exception {
        long tdfPtr = allocAndWrite(tdfBytes);
        long dekPtr = allocAndWrite(dek);

        int outCapacity = tdfBytes.length;
        long outPtr = wasmMalloc(outCapacity);

        long[] result = wasmInstance.export("tdf_decrypt").apply(
                tdfPtr, (long) tdfBytes.length,
                dekPtr, (long) dek.length,
                outPtr, (long) outCapacity
        );

        long resultLen = result[0];
        if (resultLen == 0) {
            String err = getWasmError();
            if (!err.isEmpty()) {
                throw new Exception("WASM decrypt failed: " + err);
            }
            return new byte[0];
        }

        return wasmInstance.memory().readBytes((int) outPtr, (int) resultLen);
    }

    // ── Utility methods ─────────────────────────────────────────────────

    static int[] parseSizes(String s) {
        String[] parts = s.split(",");
        int[] sizes = new int[parts.length];
        int count = 0;
        for (String p : parts) {
            p = p.trim();
            if (p.isEmpty()) continue;
            sizes[count++] = Integer.parseInt(p);
        }
        if (count < sizes.length) {
            int[] trimmed = new int[count];
            System.arraycopy(sizes, 0, trimmed, 0, count);
            return trimmed;
        }
        return sizes;
    }

    static String formatSize(int n) {
        int mb = 1024 * 1024;
        int kb = 1024;
        if (n >= mb && n % mb == 0) {
            return n / mb + " MB";
        } else if (n >= kb && n % kb == 0) {
            return n / kb + " KB";
        } else {
            return n + " B";
        }
    }

    static String fmtDurationMS(long nanos) {
        double ms = nanos / 1_000_000.0;
        return String.format("%.1f ms", ms);
    }
}
