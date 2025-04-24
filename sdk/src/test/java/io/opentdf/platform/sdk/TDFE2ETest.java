package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class TDFE2ETest {

    public class TDFConfigPair {
        public Config.TDFConfig tdfConfig;
        public Config.TDFReaderConfig tdfReaderConfig;

        public TDFConfigPair(Config.TDFConfig tdfConfig, Config.TDFReaderConfig tdfReaderConfig) {
            this.tdfConfig = tdfConfig;
            this.tdfReaderConfig = tdfReaderConfig;
        }
    }

    @Test @Disabled("this needs the backend services running to work")
    public void createAndDecryptTdfIT() throws Exception {
        var sdk = SDKBuilder
                .newBuilder()
                .clientSecret("opentdf-sdk", "secret")
                .useInsecurePlaintextConnection(true)
                .platformEndpoint("localhost:8080")
                .build();

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "localhost:8080";

        List<TDFConfigPair> tdfConfigPairs = List.of(
                new TDFConfigPair(
                        Config.newTDFConfig(Config.withKasInformation(kasInfo)),
                        Config.newTDFReaderConfig()
                ),
                new TDFConfigPair(
                        Config.newTDFConfig(Config.withKasInformation(kasInfo), Config.WithWrappingKeyAlg(KeyType.EC256Key)),
                        Config.newTDFReaderConfig(Config.WithSessionKeyType(KeyType.EC256Key))
                )
        );

        for (TDFConfigPair configPair : tdfConfigPairs) {
            String plainText = "text";
            InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
            ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

            TDF tdf = new TDF();
            tdf.createTDF(plainTextInputStream, tdfOutputStream, configPair.tdfConfig, sdk.getServices().kas(), sdk.getServices().attributes());

            var unwrappedData = new java.io.ByteArrayOutputStream();
            var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), sdk.getServices().kas(), configPair.tdfReaderConfig, sdk.getServices().kasRegistry(), sdk.getPlatformUrl());
            reader.readPayload(unwrappedData);

            assertThat(unwrappedData.toString(StandardCharsets.UTF_8)).isEqualTo("text");
        }
    }

    @Test @Disabled("this needs the backend services running to work")
    public void createAndDecryptNanoTDF() throws Exception {
        var sdk = SDKBuilder
                .newBuilder()
                .clientSecret("opentdf-sdk", "secret")
                .useInsecurePlaintextConnection(true)
                .platformEndpoint("localhost:8080")
                .buildServices()
                .services;

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://localhost:8080";

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfo)
        );

        String plainText = "text";
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF ntdf = new NanoTDF();
        ntdf.createNanoTDF(ByteBuffer.wrap(plainText.getBytes()), tdfOutputStream, config, sdk.kas());

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        ntdf.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, sdk.kas());

        String out = new String(plainTextStream.toByteArray(), "UTF-8");
        assertThat(out).isEqualTo("text");
    }
}