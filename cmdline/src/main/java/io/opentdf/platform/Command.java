package io.opentdf.platform;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.nimbusds.jose.JOSEException;
import io.opentdf.platform.sdk.AssertionConfig;
import io.opentdf.platform.sdk.AutoConfigureException;
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.KeyType;
import io.opentdf.platform.sdk.Config.AssertionVerificationKeys;
import io.opentdf.platform.sdk.NanoTDF;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.TDF;
import nl.altindag.ssl.SSLFactory;
import org.apache.commons.codec.DecoderException;
import picocli.CommandLine;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
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
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * Constants for the TDF command line tool.
 * These must be compile-time constants to appear in annotations.
 */
class Versions {
    // Version of the SDK, managed by release-please.
    public static final String SDK = "0.7.7"; // x-release-please-version

    // This sdk aims to support this version of the TDF spec; currently 4.3.0.
    public static final String TDF_SPEC = "4.3.0";
}

@CommandLine.Command(
    name = "tdf",
    subcommands = {HelpCommand.class},
    version =
        "{\"version\":\"" + Versions.SDK + "\",\"tdfSpecVersion\":\"" + Versions.TDF_SPEC + "\"}"
)
class Command {

    @Option(names = {"-V", "--version"}, versionHelp = true, description = "display version info")
    boolean versionInfoRequested;

    private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PEM_HEADER = "-----BEGIN (.*)-----";
    private static final String PEM_FOOTER = "-----END (.*)-----";

    @Option(names = { "--client-secret" }, required = true)
    private String clientSecret;

    @Option(names = { "-h", "--plaintext" }, defaultValue = "false")
    private boolean plaintext;

    @Option(names = { "-i", "--insecure" }, defaultValue = "false")
    private boolean insecure;

    @Option(names = { "--client-id" }, required = true)
    private String clientId;

    @Option(names = { "-p", "--platform-endpoint" }, required = true)
    private String platformEndpoint;

    private Object correctKeyType(AssertionConfig.AssertionKeyAlg alg, Object key, boolean publicKey) throws RuntimeException{
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
            if (publicKey){
                String base64EncodedPem= pemWithNewlines
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
            }else {
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

            throws IOException, JOSEException, AutoConfigureException, InterruptedException, ExecutionException, DecoderException {

        var sdk = buildSDK();
        var kasInfos = kas.stream().map(k -> {
            var ki = new Config.KASInfo();
            ki.URL = k;
            return ki;
        }).toArray(Config.KASInfo[]::new);

        List<Consumer<Config.TDFConfig>> configs = new ArrayList<>();
        configs.add(Config.withKasInformation(kasInfos));
        metadata.map(Config::withMetaData).ifPresent(configs::add);
        autoconfigure.map(Config::withAutoconfigure).ifPresent(configs::add);
        encapKeyType.map(Config::WithWrappingKeyAlg).ifPresent(configs::add);
        mimeType.map(Config::withMimeType).ifPresent(configs::add);

        if (assertion.isPresent()) {
            var assertionConfig = assertion.get();
            Gson gson = new Gson();

            AssertionConfig[] assertionConfigs;
            try {
                assertionConfigs = gson.fromJson(assertionConfig, AssertionConfig[].class);
            } catch (JsonSyntaxException e) {
                // try it as a file path
                try {
                    String fielJson = new String(Files.readAllBytes(Paths.get(assertionConfig)));
                    assertionConfigs = gson.fromJson(fielJson, AssertionConfig[].class);
                } catch (JsonSyntaxException e2) {
                    throw new RuntimeException("Failed to parse assertion from file, expects an list of assertions", e2);
                } catch(Exception e3) {
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
                new TDF().createTDF(in, out, tdfConfig,
                        sdk.getServices().kas(),
                        sdk.getServices().attributes());
            }
        }
    }

    private SDK buildSDK() {
        SDKBuilder builder = new SDKBuilder();
        if (insecure) {
            SSLFactory sslFactory = SSLFactory.builder()
                    .withUnsafeTrustMaterial() // Trust all certificates
                    .build();
            builder.sslFactory(sslFactory);
        }

        return builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(plaintext)
                .build();
    }

    @CommandLine.Command(name = "decrypt")
    void decrypt(@Option(names = { "-f", "--file" }, required = true) Path tdfPath,
            @Option(names = { "--rewrap-key-type" }, defaultValue = Option.NULL_VALUE, description = "Preferred rewrap algorithm, one of ${COMPLETION-CANDIDATES}") Optional<KeyType> rewrapKeyType,
            @Option(names = { "--with-assertion-verification-disabled" }, defaultValue = "false") boolean disableAssertionVerification,
            @Option(names = { "--with-assertion-verification-keys" }, defaultValue = Option.NULL_VALUE) Optional<String> assertionVerification)
             throws IOException, TDF.FailedToCreateGMAC, JOSEException, ParseException, NoSuchAlgorithmException, DecoderException {
        var sdk = buildSDK();
        var opts = new ArrayList<Consumer<Config.TDFReaderConfig>>();
        try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            try (var stdout = new BufferedOutputStream(System.out)) {
                if (assertionVerification.isPresent()) {
                    var assertionVerificationInput = assertionVerification.get();
                    Gson gson = new Gson();

                    AssertionVerificationKeys assertionVerificationKeys;
                    try {
                        assertionVerificationKeys = gson.fromJson(assertionVerificationInput, AssertionVerificationKeys.class);
                    } catch (JsonSyntaxException e) {
                        // try it as a file path
                        try {
                            String fileJson = new String(Files.readAllBytes(Paths.get(assertionVerificationInput)));
                            assertionVerificationKeys = gson.fromJson(fileJson, AssertionVerificationKeys.class);
                        } catch (JsonSyntaxException e2) {
                            throw new RuntimeException("Failed to parse assertion verification keys from file", e2);
                        } catch(Exception e3) {
                            throw new RuntimeException("Could not parse assertion verification keys as json string or path to file", e3);
                        }
                    }

                    for (Map.Entry<String, AssertionConfig.AssertionKey> entry : assertionVerificationKeys.keys.entrySet()){
                        try {
                            Object correctedKey = correctKeyType(entry.getValue().alg, entry.getValue().key, true);
                            entry.setValue(new AssertionConfig.AssertionKey(entry.getValue().alg, correctedKey));
                        } catch (Exception e) {
                            throw new RuntimeException("Error with assertion verification key: " + e.getMessage(), e);
                        }
                    }
                    opts.add(Config.withAssertionVerificationKeys(assertionVerificationKeys));
                }

                if (disableAssertionVerification) {
                    opts.add(Config.withDisableAssertionVerification(true));
                }
                rewrapKeyType.map(Config::WithSessionKeyType).ifPresent(opts::add);

                var readerConfig = Config.newTDFReaderConfig(opts.toArray(new Consumer[0]));
                var reader = new TDF().loadTDF(in, sdk.getServices().kas(), readerConfig);
                reader.readPayload(stdout);
            }
        }
    }

    @CommandLine.Command(name = "metadata")
    void readMetadata(@Option(names = { "-f", "--file" }, required = true) Path tdfPath) throws IOException,
            TDF.FailedToCreateGMAC, JOSEException, NoSuchAlgorithmException, ParseException, DecoderException {
        var sdk = buildSDK();

        try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            try (var stdout = new PrintWriter(System.out)) {
                var reader = new TDF().loadTDF(in, sdk.getServices().kas());
                stdout.write(reader.getMetadata() == null ? "" : reader.getMetadata());
            }
        }
    }

    @CommandLine.Command(name = "encryptnano")
    void createNanoTDF(
            @Option(names = { "-f", "--file" }, defaultValue = Option.NULL_VALUE) Optional<File> file,
            @Option(names = { "-k", "--kas-url" }, required = true) List<String> kas,
            @Option(names = { "-m", "--metadata" }, defaultValue = Option.NULL_VALUE) Optional<String> metadata,
            @Option(names = { "-a", "--attr" }, defaultValue = Option.NULL_VALUE) Optional<String> attributes)
            throws Exception {

        var sdk = buildSDK();
        var kasInfos = kas.stream().map(k -> {
            var ki = new Config.KASInfo();
            ki.URL = k;
            return ki;
        }).toArray(Config.KASInfo[]::new);

        List<Consumer<Config.NanoTDFConfig>> configs = new ArrayList<>();
        configs.add(Config.withNanoKasInformation(kasInfos));
        attributes.ifPresent(attr -> {
            configs.add(Config.witDataAttributes(attr.split(",")));
        });

        var nanoTDFConfig = Config.newNanoTDFConfig(configs.toArray(Consumer[]::new));
        try (var in = file.isEmpty() ? new BufferedInputStream(System.in) : new FileInputStream(file.get())) {
            try (var out = new BufferedOutputStream(System.out)) {
                NanoTDF ntdf = new NanoTDF();
                ntdf.createNanoTDF(ByteBuffer.wrap(in.readAllBytes()), out, nanoTDFConfig, sdk.getServices().kas());
            }
        }
    }

    @CommandLine.Command(name = "decryptnano")
    void readNanoTDF(@Option(names = { "-f", "--file" }, required = true) Path nanoTDFPath) throws Exception {
        var sdk = buildSDK();
        try (var in = FileChannel.open(nanoTDFPath, StandardOpenOption.READ)) {
            try (var stdout = new BufferedOutputStream(System.out)) {
                NanoTDF ntdf = new NanoTDF();
                ByteBuffer buffer = ByteBuffer.allocate((int) in.size());
                in.read(buffer);
                buffer.flip();
                ntdf.readNanoTDF(buffer, stdout, sdk.getServices().kas());
            }
        }
    }
}
