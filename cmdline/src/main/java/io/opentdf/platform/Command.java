package io.opentdf.platform;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

import io.opentdf.platform.sdk.AssertionConfig;
import io.opentdf.platform.sdk.AutoConfigureException;
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import picocli.CommandLine;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;
/**
 * Constants for the TDF command line tool.
 * These must be compile-time constants to appear in annotations.
 */
class Versions {
    // Version of the SDK, managed by release-please.
    public static final String SDK = "0.17.1"; // x-release-please-version

    // This sdk aims to support this version of the TDF spec; currently 4.3.0.
    public static final String TDF_SPEC = "4.3.0";
}

@CommandLine.Command(name = "tdf", subcommands = { HelpCommand.class,
        Command.Supports.class }, version = "{\"version\":\"" + Versions.SDK
                + "\",\"tdfSpecVersion\":\"" + Versions.TDF_SPEC + "\"}")
class Command {
    @Option(names = { "-V", "--version" }, versionHelp = true, description = "display version info")
    boolean versionInfoRequested;

    @CommandLine.Command(name = "supports", description = "Check if a feature is supported")
    static class Supports implements Callable<Integer> {
        @CommandLine.Parameters(index = "0", description = "Feature to check (e.g., dpop)")
        private String feature;

        @Override
        public Integer call() {
            return ("dpop".equalsIgnoreCase(feature) || "dpop_nonce_challenge".equalsIgnoreCase(feature)) ? 0 : 1;
        }
    }

    private static class AssertionKeyDeserializer implements JsonDeserializer<AssertionConfig.AssertionKey> {
        @Override
        public AssertionConfig.AssertionKey deserialize(JsonElement json, java.lang.reflect.Type typeOfT,
                JsonDeserializationContext context) throws JsonParseException {
            JsonObject jsonObject = json.getAsJsonObject();
            AssertionConfig.AssertionKey assertionKey = new AssertionConfig.AssertionKey(
                    AssertionConfig.AssertionKeyAlg.NotDefined, null);

            if (jsonObject.has("alg")) {
                assertionKey.alg = context.deserialize(jsonObject.get("alg"), AssertionConfig.AssertionKeyAlg.class);
            }
            if (jsonObject.has("key")) {
                assertionKey.key = context.deserialize(jsonObject.get("key"), Object.class);
            }
            if (jsonObject.has("jwk")) {
                try {
                    assertionKey.jwk = com.nimbusds.jose.jwk.JWK.parse(jsonObject.get("jwk").toString());
                } catch (ParseException e) {
                    throw new JsonParseException("Failed to parse jwk", e);
                }
            }
            if (jsonObject.has("x5c")) {
                assertionKey.x5c = context.deserialize(jsonObject.get("x5c"),
                        new TypeToken<List<com.nimbusds.jose.util.Base64>>() {
                        }.getType());
            }

            return assertionKey;
        }
    }

    private Gson buildGson() {
        return new GsonBuilder()
                .registerTypeAdapter(AssertionConfig.AssertionKey.class, new AssertionKeyDeserializer())
                .create();
    }

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PEM_HEADER = "-----BEGIN (.*)-----";
    private static final String PEM_FOOTER = "-----END (.*)-----";

    @Option(names = { "--client-secret" })
    private String clientSecret;

    @Option(names = { "-h", "--plaintext" }, defaultValue = "false")
    private boolean plaintext;

    @Option(names = { "-i", "--insecure" }, defaultValue = "false")
    private boolean insecure;

    @Option(names = { "--client-id" })
    private String clientId;

    @Option(names = { "-p", "--platform-endpoint" })
    private String platformEndpoint;

    @Option(names = {
            "--dpop" }, arity = "0..1", fallbackValue = "", scope = CommandLine.ScopeType.INHERIT, description = "Enable DPoP (RFC 9449). Optional: specify algorithm (RS256, RS384, RS512, ES256, ES384, ES512). Default: RS256.")
    private String dpopAlg;

    @Option(names = {
            "--dpop-key" }, scope = CommandLine.ScopeType.INHERIT, description = "Enable DPoP using a PEM-encoded private key at <path>. Algorithm inferred from key type. Combinable with --dpop=<alg>.")
    private Path dpopKeyPath;

    private Object correctKeyType(AssertionConfig.AssertionKeyAlg alg, Object key, boolean publicKey)
            throws RuntimeException {
        if (alg == AssertionConfig.AssertionKeyAlg.HS256) {
            if (key instanceof String) {
                key = ((String) key).getBytes(StandardCharsets.UTF_8);
                return key;
            } else if (key instanceof byte[]) {
                return key;
            } else {
                throw new RuntimeException("Unexpected type for assertion key");
            }
        } else if (alg == AssertionConfig.AssertionKeyAlg.RS256) {
            if (!(key instanceof String)) {
                throw new RuntimeException("Unexpected type for assertion key");
            }
            String pem = (String) key;
            String pemWithNewlines = pem.replace("\\n", "\n");
            if (publicKey) {
                String base64EncodedPem = pemWithNewlines
                        .replaceAll(PEM_HEADER, "")
                        .replaceAll(PEM_FOOTER, "")
                        .replaceAll("\\s", "")
                        .replaceAll("\r\n", "")
                        .replaceAll("\n", "")
                        .trim();
                byte[] decoded = Base64.getDecoder().decode(base64EncodedPem);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
                KeyFactory kf = null;
                try {
                    kf = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                try {
                    return kf.generatePublic(spec);
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
            } else {
                String privateKeyPEM = pemWithNewlines
                        .replace(PRIVATE_KEY_HEADER, "")
                        .replace(PRIVATE_KEY_FOOTER, "")
                        .replaceAll("\\s", ""); // remove whitespaces

                byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);

                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
                KeyFactory kf = null;
                try {
                    kf = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                try {
                    return kf.generatePrivate(spec);
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return null;
    }

    @CommandLine.Command(name = "encrypt")
    void encrypt(
            @Option(names = { "-f", "--file" }, defaultValue = Option.NULL_VALUE) Optional<File> file,
            @Option(names = { "-k", "--kas-url" }, required = true, split = ",") List<String> kas,
            @Option(names = { "-m", "--metadata" }, defaultValue = Option.NULL_VALUE) Optional<String> metadata,
            // cant split on optional parameters
            @Option(names = { "-a", "--attr" }, defaultValue = Option.NULL_VALUE) Optional<String> attributes,
            @Option(names = { "-c",
                    "--autoconfigure" }, defaultValue = Option.NULL_VALUE) Optional<Boolean> autoconfigure,
            @Option(names = {
                    "--encap-key-type" }, defaultValue = Option.NULL_VALUE, description = "Preferred key access key wrap algorithm, one of ${COMPLETION-CANDIDATES}") Optional<KeyType> encapKeyType,
            @Option(names = { "--mime-type" }, defaultValue = Option.NULL_VALUE) Optional<String> mimeType,
            @Option(names = { "--with-assertions" }, defaultValue = Option.NULL_VALUE) Optional<String> assertion,
            @Option(names = { "--with-target-mode" }, defaultValue = Option.NULL_VALUE) Optional<String> targetMode)

            throws IOException, AutoConfigureException {

        var sdk = buildSDK();
        var kasInfos = kas.stream().map(k -> {
            var ki = new Config.KASInfo();
            ki.URL = k;
            return ki;
        }).toArray(Config.KASInfo[]::new);

        List<Consumer<Config.TDFConfig>> configs = new ArrayList<>();
        configs.add(Config.withKasInformation(kasInfos));
        metadata.map(Config::withMetaData).ifPresent(configs::add);
        configs.add(Config.withSystemMetadataAssertion());
        autoconfigure.map(Config::withAutoconfigure).ifPresent(configs::add);
        encapKeyType.map(Config::WithWrappingKeyAlg).ifPresent(configs::add);
        mimeType.map(Config::withMimeType).ifPresent(configs::add);

        if (assertion.isPresent()) {
            var assertionConfig = assertion.get();
            Gson gson = buildGson();

            AssertionConfig[] assertionConfigs;
            try {
                assertionConfigs = gson.fromJson(assertionConfig, AssertionConfig[].class);
            } catch (JsonSyntaxException e) {
                // try it as a file path
                try {
                    String fileJson = new String(Files.readAllBytes(Paths.get(assertionConfig)));
                    assertionConfigs = gson.fromJson(fileJson, AssertionConfig[].class);
                } catch (JsonSyntaxException e2) {
                    throw new RuntimeException("Failed to parse assertion from file, expects an list of assertions",
                            e2);
                } catch (Exception e3) {
                    throw new RuntimeException("Could not parse assertion as json string or path to file", e3);
                }
            }
            // iterate through the assertions and correct the key types
            for (int i = 0; i < assertionConfigs.length; i++) {
                AssertionConfig config = assertionConfigs[i];
                if (config.signingKey != null && config.signingKey.isDefined()) {
                    try {
                        Object correctedKey = correctKeyType(config.signingKey.alg, config.signingKey.key, false);
                        config.signingKey.key = correctedKey;
                    } catch (Exception e) {
                        throw new RuntimeException("Error with assertion signing key: " + e.getMessage(), e);
                    }
                }
                assertionConfigs[i] = config;
            }
            configs.add(Config.withAssertionConfig(assertionConfigs));
        }

        attributes.ifPresent(s -> configs.add(Config.withDataAttributes(s.split(","))));
        targetMode.map(Config::withTargetMode).ifPresent(configs::add);
        var tdfConfig = Config.newTDFConfig(configs.toArray(Consumer[]::new));
        try (var in = file.isEmpty() ? new BufferedInputStream(System.in) : new FileInputStream(file.get())) {
            try (var out = new BufferedOutputStream(System.out)) {
                sdk.createTDF(in, out, tdfConfig);
            }
        }
    }

    private SDK buildSDK() {
        SDKBuilder builder = new SDKBuilder();
        if (insecure) {
            builder.insecureSslFactory();
        }

        applyDPoPOptions(builder);

        return builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(plaintext)
                .build();
    }

    /**
     * Apply --dpop and --dpop-key options to the SDK builder.
     * --dpop-key loads a PEM private key; --dpop specifies the algorithm (default
     * RS256).
     * If neither flag is set, the SDK auto-generates an ephemeral RSA-2048 DPoP
     * key.
     */
    private void applyDPoPOptions(SDKBuilder builder) {
        try {
            if (dpopKeyPath != null) {
                String pem = Files.readString(dpopKeyPath);
                JWK jwk = JWK.parseFromPEMEncodedObjects(pem);
                builder.dpopKey(jwk);
                if (dpopAlg != null && !dpopAlg.isEmpty()) {
                    builder.dpopAlgorithm(parseAlgorithm(dpopAlg));
                }
            } else if (dpopAlg != null) {
                JWSAlgorithm alg = dpopAlg.isEmpty() ? JWSAlgorithm.RS256 : parseAlgorithm(dpopAlg);
                JWK jwk = generateKeyForAlgorithm(alg);
                builder.dpopKey(jwk).dpopAlgorithm(alg);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure DPoP: " + e.getMessage(), e);
        }
    }

    private static JWSAlgorithm parseAlgorithm(String alg) {
        switch (alg.toUpperCase()) {
            case "RS256":
                return JWSAlgorithm.RS256;
            case "RS384":
                return JWSAlgorithm.RS384;
            case "RS512":
                return JWSAlgorithm.RS512;
            case "ES256":
                return JWSAlgorithm.ES256;
            case "ES384":
                return JWSAlgorithm.ES384;
            case "ES512":
                return JWSAlgorithm.ES512;
            default:
                throw new RuntimeException("Unsupported DPoP algorithm: " + alg
                        + ". Supported: RS256, RS384, RS512, ES256, ES384, ES512");
        }
    }

    private static JWK generateKeyForAlgorithm(JWSAlgorithm alg) throws Exception {
        if (JWSAlgorithm.RS256.equals(alg) || JWSAlgorithm.RS384.equals(alg) || JWSAlgorithm.RS512.equals(alg)) {
            return new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } else if (JWSAlgorithm.ES256.equals(alg)) {
            return new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } else if (JWSAlgorithm.ES384.equals(alg)) {
            return new ECKeyGenerator(Curve.P_384)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } else if (JWSAlgorithm.ES512.equals(alg)) {
            return new ECKeyGenerator(Curve.P_521)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        }
        throw new RuntimeException("Cannot generate key for algorithm: " + alg);
    }

    @CommandLine.Command(name = "decrypt")
    void decrypt(
            @Option(names = { "-f", "--file" }, required = true) Path tdfPath,
            @Option(names = {
                    "--rewrap-key-type" }, defaultValue = Option.NULL_VALUE, description = "Preferred rewrap algorithm, one of ${COMPLETION-CANDIDATES}") Optional<KeyType> rewrapKeyType,
            @Option(names = {
                    "--with-assertion-verification-disabled" }, defaultValue = "false") boolean disableAssertionVerification,
            @Option(names = {
                    "--with-assertion-verification-keys" }, defaultValue = Option.NULL_VALUE) Optional<String> assertionVerification,
            @Option(names = { "--kas-allowlist" }, defaultValue = Option.NULL_VALUE) Optional<String> kasAllowlistStr,
            @Option(names = {
                    "--ignore-kas-allowlist" }, defaultValue = Option.NULL_VALUE) Optional<Boolean> ignoreAllowlist)
            throws Exception {
        try (var sdk = buildSDK()) {
            var opts = new ArrayList<Consumer<Config.TDFReaderConfig>>();
            try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
                try (var stdout = new BufferedOutputStream(System.out)) {
                    if (assertionVerification.isPresent()) {
                        var assertionVerificationInput = assertionVerification.get();
                        Gson gson = buildGson();

                        Config.AssertionVerificationKeys assertionVerificationKeys;
                        try {
                            assertionVerificationKeys = gson.fromJson(assertionVerificationInput,
                                    Config.AssertionVerificationKeys.class);
                        } catch (JsonSyntaxException e) {
                            // try it as a file path
                            try {
                                String fileJson = new String(Files.readAllBytes(Paths.get(assertionVerificationInput)));
                                assertionVerificationKeys = gson.fromJson(fileJson,
                                        Config.AssertionVerificationKeys.class);
                            } catch (JsonSyntaxException e2) {
                                throw new RuntimeException("Failed to parse assertion verification keys from file", e2);
                            } catch (Exception e3) {
                                throw new RuntimeException(
                                        "Could not parse assertion verification keys as json string or path to file",
                                        e3);
                            }
                        }

                        for (Map.Entry<String, AssertionConfig.AssertionKey> entry : assertionVerificationKeys.keys
                                .entrySet()) {
                            try {
                                Object correctedKey = correctKeyType(entry.getValue().alg, entry.getValue().key, true);
                                entry.setValue(new AssertionConfig.AssertionKey(entry.getValue().alg, correctedKey));
                            } catch (Exception e) {
                                throw new RuntimeException("Error with assertion verification key: " + e.getMessage(),
                                        e);
                            }
                        }
                        opts.add(Config.withAssertionVerificationKeys(assertionVerificationKeys));
                    }

                    if (disableAssertionVerification) {
                        opts.add(Config.withDisableAssertionVerification(true));
                    }
                    rewrapKeyType.map(Config::WithSessionKeyType).ifPresent(opts::add);

                    ignoreAllowlist.ifPresent(aBoolean -> opts.add(Config.WithIgnoreKasAllowlist(aBoolean)));
                    kasAllowlistStr.ifPresent(s -> opts.add(Config.WithKasAllowlist(s.split(","))));

                    var readerConfig = Config.newTDFReaderConfig(opts.toArray(new Consumer[0]));
                    var reader = sdk.loadTDF(in, readerConfig);
                    reader.readPayload(stdout);
                }
            }
        }
    }

    @CommandLine.Command(name = "metadata")
    void readMetadata(
            @Option(names = { "-f", "--file" }, required = true) Path tdfPath,
            @Option(names = { "--kas-allowlist" }, defaultValue = Option.NULL_VALUE) Optional<String> kasAllowlistStr,
            @Option(names = {
                    "--ignore-kas-allowlist" }, defaultValue = Option.NULL_VALUE) Optional<Boolean> ignoreAllowlist)
            throws IOException {
        var sdk = buildSDK();
        var opts = new ArrayList<Consumer<Config.TDFReaderConfig>>();
        try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            try (var stdout = new PrintWriter(System.out)) {

                ignoreAllowlist.map(Config::WithIgnoreKasAllowlist).ifPresent(opts::add);
                kasAllowlistStr.map(s -> s.split(",")).map(Config::WithKasAllowlist).ifPresent(opts::add);

                var readerConfig = Config.newTDFReaderConfig(opts.toArray(new Consumer[0]));
                var reader = sdk.loadTDF(in, readerConfig);
                stdout.write(reader.getMetadata() == null ? "" : reader.getMetadata());
            }
        }
    }
}
