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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class TDFE2ETest {

    @Test @Disabled("this needs the backend services running to work")
    public void createAndDecryptTdfIT() throws Exception {
        var sdk = SDKBuilder
                .newBuilder()
                .clientSecret("opentdf-sdk", "secret")
                .useInsecurePlaintextConnection(true)
                .platformEndpoint("localhost:8080")
                .buildServices();

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "localhost:8080";
        Config.TDFConfig config = Config.newTDFConfig(Config.withKasInformation(kasInfo));

        String plainText = "text";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, sdk.kas());

        var unwrappedData = new java.io.ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), sdk.kas());
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8)).isEqualTo("text");
    }

    @Test @Disabled("this needs the backend services running to work")
    public void createAndDecryptNanoTDF() throws Exception {
        var sdk = SDKBuilder
                .newBuilder()
                .clientSecret("opentdf-sdk", "secret")
                .useInsecurePlaintextConnection(true)
                .platformEndpoint("localhost:8080")
                .buildServices();

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