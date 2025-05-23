package io.opentdf.platform;

import io.opentdf.platform.sdk.*;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import com.nimbusds.jose.JOSEException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.cli.*;
import org.apache.commons.codec.DecoderException;

public class DecryptExample {
    public static void main(String[] args) throws IOException, ParseException {

        // Create Options object
        Options options = new Options();

        // Add rewrap encapsulation algorithm option
        options.addOption(Option.builder("A")
                .longOpt("rewrap-encapsulation-algorithm")
                .hasArg()
                .desc("Key wrap response algorithm algorithm:parameters")
                .build());

        // Parse command line arguments
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        // Get the rewrap encapsulation algorithm
        String rewrapEncapsulationAlgorithm = cmd.getOptionValue("rewrap-encapsulation-algorithm", "rsa:2048");
        var sessionKeyType = KeyType.fromString(rewrapEncapsulationAlgorithm.toLowerCase());


        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        Path path = Paths.get("my.ciphertext");
        try (var in = FileChannel.open(path, StandardOpenOption.READ)) {
            var reader = sdk.loadTDF(in, Config.newTDFReaderConfig(Config.WithSessionKeyType(sessionKeyType)));
            reader.readPayload(System.out);
        }

        // Print the rewrap encapsulation algorithm
        System.out.println("Rewrap Encapsulation Algorithm: " + rewrapEncapsulationAlgorithm);
    }
}