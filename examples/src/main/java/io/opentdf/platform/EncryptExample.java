package io.opentdf.platform;

import io.opentdf.platform.sdk.*;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.io.FileOutputStream;
import com.nimbusds.jose.JOSEException;
import org.apache.commons.cli.*;
import org.apache.commons.codec.DecoderException;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class EncryptExample {
    public static void main(String[] args) throws IOException, ParseException {
        // Create Options object
        Options options = new Options();

        // Add key encapsulation algorithm option
        options.addOption(Option.builder("A")
                .longOpt("key-encapsulation-algorithm")
                .hasArg()
                .desc("Key wrap algorithm algorithm:parameters")
                .build());

        // Parse command line arguments
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        // Get the key encapsulation algorithm
        String keyEncapsulationAlgorithm = cmd.getOptionValue("key-encapsulation-algorithm", "rsa:2048");

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://localhost:8080/kas";

        var wrappingKeyType = KeyType.fromString(keyEncapsulationAlgorithm.toLowerCase());
        var tdfConfig = Config.newTDFConfig(Config.withKasInformation(kasInfo),
                Config.withDataAttributes("https://example.com/attr/color/value/red"),
                Config.WithWrappingKeyAlg(wrappingKeyType));
        String str = "Hello, World!";

        // Convert String to InputStream
        var in = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));

        FileOutputStream fos = new FileOutputStream("my.ciphertext");

        Manifest manifest = sdk.createTDF(in, fos, tdfConfig);
    }
}