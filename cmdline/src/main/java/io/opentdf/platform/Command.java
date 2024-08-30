package io.opentdf.platform;

import com.nimbusds.jose.JOSEException;
import io.opentdf.platform.sdk.*;
import io.opentdf.platform.sdk.TDF;

import org.apache.commons.codec.DecoderException;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.TrustManagerUtils;

import javax.net.ssl.TrustManager;

@CommandLine.Command(name = "tdf")
class Command {

    @Option(names = {"--client-secret"}, required = true)
    private String clientSecret;

    @Option(names = {"-h", "--plaintext"}, defaultValue = "false")
    private boolean plaintext;

    @Option(names = {"-i", "--insecure"}, defaultValue = "false")
    private boolean insecure;

    @Option(names = {"--client-id"}, required = true)
    private String clientId;

    @Option(names = {"-p", "--platform-endpoint"}, required = true)
    private String platformEndpoint;

    @CommandLine.Command(name = "encrypt")
    void encrypt(
            @Option(names = {"-f", "--file"}, defaultValue = Option.NULL_VALUE) Optional<File> file,
            @Option(names = {"-k", "--kas-url"}, required = true, split = ",") List<String> kas,
            @Option(names = {"-m", "--metadata"}, defaultValue = Option.NULL_VALUE) Optional<String> metadata,
            // cant split on optional parameters
            @Option(names = {"-a", "--attr"}, defaultValue = Option.NULL_VALUE) Optional<String> attributes,
            @Option(names = {"-c", "--autoconfigure"}, defaultValue = Option.NULL_VALUE) Optional<Boolean> autoconfigure,
            @Option(names = {"--mime-type"}, defaultValue = Option.NULL_VALUE) Optional<String> mimeType) throws
            IOException, JOSEException, AutoConfigureException, InterruptedException, ExecutionException {

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
        mimeType.map(Config::withMimeType).ifPresent(configs::add);
        if (attributes.isPresent()){
            configs.add(Config.withDataAttributes(attributes.get().split(",")));
        }
        var tdfConfig = Config.newTDFConfig(configs.toArray(Consumer[]::new));
        try (var in = file.isEmpty() ? new BufferedInputStream(System.in) : new FileInputStream(file.get())) {
            try (var out = new BufferedOutputStream(System.out)) {
                new TDF().createTDF(in, out, tdfConfig, 
                    sdk.getServices().kas(), 
                    sdk.getServices().attributes()
                );
            }
        }
    }

    private SDK buildSDK() {
        SDKBuilder builder = new SDKBuilder();
        if (insecure){
            SSLFactory sslFactory = SSLFactory.builder()
            .withUnsafeTrustMaterial() // Trust all certificates
            .build();
            builder.sslFactory(sslFactory);
        }
        
        return  builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret)
                .useInsecurePlaintextConnection(plaintext)
                .build();
    }

    @CommandLine.Command(name = "decrypt")
    void decrypt(@Option(names = {"-f", "--file"}, required = true) Path tdfPath) throws IOException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException, TDF.FailedToCreateGMAC,
            JOSEException, ParseException, NoSuchAlgorithmException, DecoderException {
        var sdk = buildSDK();
        try (var in = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            try (var stdout = new BufferedOutputStream(System.out)) {
                    var reader = new TDF().loadTDF(in, sdk.getServices().kas());
                    reader.readPayload(stdout);
                }
        }
    }
    @CommandLine.Command(name = "metadata")
    void readMetadata(@Option(names = {"-f", "--file"}, required = true) Path tdfPath) throws IOException,
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
            @Option(names = {"-f", "--file"}, defaultValue = Option.NULL_VALUE) Optional<File> file,
            @Option(names = {"-k", "--kas-url"}, required = true) List<String> kas,
            @Option(names = {"-m", "--metadata"}, defaultValue = Option.NULL_VALUE) Optional<String> metadata,
            @Option(names = {"-a", "--attr"}, defaultValue = Option.NULL_VALUE) Optional<String> attributes) throws Exception {

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
    void readNanoTDF(@Option(names = {"-f", "--file"}, required = true) Path nanoTDFPath) throws Exception {
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
