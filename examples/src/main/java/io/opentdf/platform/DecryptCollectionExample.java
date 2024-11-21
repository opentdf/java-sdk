package io.opentdf.platform;

import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.NanoTDF;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class DecryptCollectionExample {
    public static void main(String[] args) throws IOException, NanoTDF.NanoTDFMaxSizeLimit, NanoTDF.UnsupportedNanoTDFFeature, NanoTDF.InvalidNanoTDFConfig, NoSuchAlgorithmException, InterruptedException {
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
        NanoTDF nanoTDFClient = new NanoTDF(true);

        for (int i = 0; i < 50; i++) {
            FileInputStream fis = new FileInputStream(String.format("out/my.%d_ciphertext", i));
            nanoTDFClient.readNanoTDF(ByteBuffer.wrap(fis.readAllBytes()), System.out, sdk.getServices().kas());
            fis.close();
        }

    }
}
