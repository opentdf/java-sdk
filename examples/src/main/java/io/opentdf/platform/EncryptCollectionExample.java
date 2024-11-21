package io.opentdf.platform;

import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.NanoTDF;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class EncryptCollectionExample {
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

        var tdfConfig = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfo),
                Config.witDataAttributes("https://example.com/attr/attr1/value/value1"),
                Config.withCollection()
        );

        String str = "Hello, World!";

        // Convert String to InputStream
        var in = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));
        NanoTDF nanoTDFClient = new NanoTDF();

        for (int i = 0; i < 50; i++) {
            FileOutputStream fos = new FileOutputStream(String.format("out/my.%d_ciphertext", i));
            nanoTDFClient.createNanoTDF(ByteBuffer.wrap(str.getBytes()), fos, tdfConfig,
                    sdk.getServices().kas());
        }

    }
}
