package io.opentdf.platform;

import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.TDF;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

@CommandLine.Command(name = "tdf")
class Command {

    @Option(names = {"--client-secret"}, required = true)
    private String clientSecret;

    @Option(names = {"-i", "--insecure-connection"}, defaultValue = "false")
    private boolean insecure;

    @Option(names = {"--client-id"}, required = true)
    private String clientId;

    @Option(names = {"-p", "--platform-endpoint"}, required = true)
    private String platformEndpoint;

    @CommandLine.Command(name = "encrypt")
    void encrypt(
            @Option(names = {"-f", "--file"}, defaultValue = Option.NULL_VALUE) Optional<File> file,
            @Option(names = {"-k", "--kas-url"}, required = true) List<String> kas,
            @Option(names = {"-m", "--metadata"}, defaultValue = Option.NULL_VALUE) Optional<String> metadata) throws IOException {

        var sdk = buildSDK();
        var kasInfos = kas.stream().map(k -> {
            var ki = new Config.KASInfo();
            ki.URL = k;
            return ki;
        }).toArray(Config.KASInfo[]::new);

        List<Consumer<Config.TDFConfig>> configs = new ArrayList<>();
        configs.add(Config.withKasInformation(kasInfos));
        metadata.map(Config::withMetaData).ifPresent(configs::add);

        var tdfConfig = Config.newTDFConfig(configs.toArray(Consumer[]::new));
        try (var in = file.isEmpty() ? new BufferedInputStream(System.in) : new FileInputStream(file.get())) {
            try (var out = new BufferedOutputStream(System.out)) {
                new TDF().createTDF(in, out, tdfConfig, sdk.getServices().kas());
            }
        }
    }

    private SDK buildSDK() {
        return new SDKBuilder()
                .platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret)
                .useInsecurePlaintextConnection(insecure)
                .build();
    }

    @CommandLine.Command(name = "decrypt")
    void decrypt(@Option(names = {"-f", "--file"}, required = true) Path tdfPath) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var sdk = buildSDK();
        try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            try (var stdout = new BufferedOutputStream(System.out)) {
                    var reader = new TDF().loadTDF(in, sdk.getServices().kas());
                    reader.readPayload(stdout);
                }
        }
    }
    @CommandLine.Command(name = "metadata")
    void readMetadata(@Option(names = {"-f", "--file"}, required = true) Path tdfPath) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        var sdk = buildSDK();

        try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            try (var stdout = new PrintWriter(System.out)) {
                var reader = new TDF().loadTDF(in, sdk.getServices().kas());
                stdout.write(reader.getMetadata() == null ? "" : reader.getMetadata());
            }
        }
    }
}
