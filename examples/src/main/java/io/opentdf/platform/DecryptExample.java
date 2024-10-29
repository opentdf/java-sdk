package io.opentdf.platform;
import io.opentdf.platform.sdk.*;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.nimbusds.jose.JOSEException;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.DecoderException;


public class DecryptExample {
    public static void main(String[] args) throws IOException,
    InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
    BadPaddingException, InvalidKeyException, TDF.FailedToCreateGMAC,
    JOSEException, ParseException, NoSuchAlgorithmException, DecoderException {

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        Path path = Paths.get("my.ciphertext");
        try (var in = FileChannel.open(path, StandardOpenOption.READ)) {
            var reader = new TDF().loadTDF(in, sdk.getServices().kas(), new Config.TDFReaderConfig());
            reader.readPayload(System.out);
        }
    }
}
