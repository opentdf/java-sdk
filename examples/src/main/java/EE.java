import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.TDF;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;

public class EE {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        SDK sdk = new SDKBuilder()
                        .clientSecret("myClient", "token")
                        .platformEndpoint("https://your.cluster/")
                        .build();
        // Encrypt a file
        try (InputStream in = new FileInputStream("input.plaintext")) {
            Config.TDFConfig c = Config.newTDFConfig(Config.withDataAttributes("attr1", "attr2"));
            sdk.createTDF(in, System.out, c);
        }

        // Decrypt a file
        try (SeekableByteChannel in = FileChannel.open(Path.of("input.ciphertext"), StandardOpenOption.READ)) {
            TDF.Reader reader = sdk.loadTDF(in, Config.newTDFReaderConfig());
            reader.readPayload(System.out);
        }
    }
}
