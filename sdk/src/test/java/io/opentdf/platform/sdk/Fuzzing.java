package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URISyntaxException;
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
    private static final String TEST_DURATION = "600s";
    private static final OutputStream IGNORE_OUTPUT_STREAM = new OutputStream() {
        @Override
        public void write(int b) {
            // ignored
        }

        @Override
        public void write(byte[] b, int off, int len) {
            // ignored
        }
    };

    @FuzzTest(maxDuration=TEST_DURATION)
    public void fuzzNanoTDF(FuzzedDataProvider data) throws IOException, URISyntaxException {
        byte[] fuzzBytes = data.consumeRemainingAsBytes();
        NanoTDF nanoTDF = new NanoTDF();
        nanoTDF.readNanoTDF(ByteBuffer.wrap(fuzzBytes), IGNORE_OUTPUT_STREAM, NanoTDFTest.kas);
    }

    @FuzzTest(maxDuration=TEST_DURATION)
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

            reader.readPayload(IGNORE_OUTPUT_STREAM);
        } catch (SDKException | InvalidZipException | JsonParseException | IOException | IllegalArgumentException e) {
            // expected failure cases
        }
    }

    @FuzzTest(maxDuration=TEST_DURATION)
    public void fuzzZipRead(FuzzedDataProvider data) {
        byte[] fuzzBytes = data.consumeRemainingAsBytes();
        try {
            ZipReaderTest.testReadingZipChannel(new SeekableInMemoryByteChannel(fuzzBytes), false);
        } catch (InvalidZipException | IllegalArgumentException | JsonParseException | IOException e) {
            // cases which are expected with invalid fuzzed inputs
        }
    }
}
