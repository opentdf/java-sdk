package io.opentdf.platform;
import io.opentdf.platform.sdk.*;
import java.io.ByteArrayInputStream;
import java.io.BufferedOutputStream;
import java.nio.charset.StandardCharsets;
import java.io.FileOutputStream;

import com.nimbusds.jose.JOSEException;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class EncryptExample {
    public static void main(String[] args) throws IOException, JOSEException, AutoConfigureException, InterruptedException, ExecutionException {
        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://localhost:8080/kas";

        var tdfConfig = Config.newTDFConfig(Config.withKasInformation(kasInfo), Config.withDataAttributes("https://example.com/attr/color/value/red"));

        String str = "Hello, World!";
        
        // Convert String to InputStream
        var in = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));

        FileOutputStream fos = new FileOutputStream("my.ciphertext");

        new TDF().createTDF(in, fos, tdfConfig,
                        sdk.getServices().kas(),
                        sdk.getServices().attributes());
    }
}
