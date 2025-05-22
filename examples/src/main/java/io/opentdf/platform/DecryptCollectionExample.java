package io.opentdf.platform;

import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class DecryptCollectionExample {
    public static void main(String[] args) throws IOException {
        String clientId = "opentdf-sdk";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://localhost:8080/kas";


        // Convert String to InputStream
        for (int i = 0; i < 50; i++) {
            FileInputStream fis = new FileInputStream(String.format("out/my.%d_ciphertext", i));
            sdk.readNanoTDF(ByteBuffer.wrap(fis.readAllBytes()), System.out, Config.newNanoTDFReaderConfig());
            fis.close();
        }

    }
}
