package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.google.gson.JsonParseException;
import com.nimbusds.jose.JOSEException;

import io.opentdf.platform.sdk.TDF.FailedToCreateGMAC;
import io.opentdf.platform.sdk.TDF.Reader;

public class Fuzzing {
    private static final String testDuration = "600s";
    private static final OutputStream ignoreOutputStream = new OutputStream() {
        @Override
        public void write(int b) {
            // ignored
        }

        @Override
        public void write(byte b[], int off, int len) {
            // ignored
        }
    };

    @FuzzTest(maxDuration=testDuration)
    public void fuzzNanoTDF(FuzzedDataProvider data) throws IOException {
        byte[] fuzzBytes = data.consumeRemainingAsBytes();
        NanoTDF nanoTDF = new NanoTDF();
        nanoTDF.readNanoTDF(ByteBuffer.wrap(fuzzBytes), ignoreOutputStream, NanoTDFTest.kas);
    }

    @FuzzTest(maxDuration=testDuration)
    public void fuzzTDF(FuzzedDataProvider data) throws FailedToCreateGMAC, NoSuchAlgorithmException, IOException, JOSEException, ParseException, DecoderException {
        byte[] fuzzBytes = data.consumeRemainingAsBytes();
        byte[] key = new byte[32];      // use consistent zero key for performance and so fuzz can relate to seed
        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.defaultKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);
        Config.TDFReaderConfig readerConfig = Config.newTDFReaderConfig(
                Config.withAssertionVerificationKeys(assertionVerificationKeys));
        TDF tdf = new TDF();

        try {
            Reader reader = tdf.loadTDF(new SeekableInMemoryByteChannel(fuzzBytes), TDFTest.kas, readerConfig);

            reader.readPayload(ignoreOutputStream);
        } catch (SDKException | InvalidZipException | JsonParseException | IOException | IllegalArgumentException e) {
            // expected failure cases
        }
    }

    @FuzzTest(maxDuration=testDuration)
    public void fuzzZipRead(FuzzedDataProvider data) {
        byte[] fuzzBytes = data.consumeRemainingAsBytes();
        try {
            ZipReaderTest.testReadingZipChannel(new SeekableInMemoryByteChannel(fuzzBytes), false);
        } catch (InvalidZipException | IllegalArgumentException | JsonParseException | IOException e) {
            // cases which are expected with invalid fuzzed inputs
        }
    }
}
