package io.opentdf.platform.sdk;

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
        kasInfo.setURL("localhost:8080");

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

            TDF tdf = new TDF(sdk.getServices());
            tdf.createTDF(plainTextInputStream, tdfOutputStream, configPair.tdfConfig);

            var unwrappedData = new java.io.ByteArrayOutputStream();
            var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), configPair.tdfReaderConfig, sdk.getPlatformUrl());
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
        kasInfo.setURL("http://localhost:8080");

        for (NanoTDFType.PolicyType policyType : List.of(
                NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT,
                NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED)) {

            Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                    Config.withNanoKasInformation(kasInfo),
                    Config.withPolicyType(policyType)
            );

            String plainText = "text";
            ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

            NanoTDF ntdf = new NanoTDF(sdk);
            ntdf.createNanoTDF(ByteBuffer.wrap(plainText.getBytes()), tdfOutputStream, config);

            byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
            ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
            ntdf.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream,
                    Config.newNanoTDFReaderConfig(Config.WithNanoIgnoreKasAllowlist(true)));

            String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
            assertThat(out).isEqualTo("text");
        }
    }
}