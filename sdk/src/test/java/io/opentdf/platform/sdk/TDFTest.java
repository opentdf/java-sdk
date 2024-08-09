package io.opentdf.platform.sdk;


import com.nimbusds.jose.jwk.RSAKey;

import io.opentdf.platform.sdk.TDF.TDFObject;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TDFTest {

    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public void close() {}

        @Override
        public String getPublicKey(Config.KASInfo kasInfo) {
            int index = Integer.parseInt(kasInfo.URL);

            return CryptoUtils.getRSAPublicKeyPEM(keypairs.get(index).getPublic());
        }

        @Override
        public String getKid(Config.KASInfo kasInfo) {
            return "r1";
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy) {
            int index = Integer.parseInt(keyAccess.url);
            var decryptor = new AsymDecryption(keypairs.get(index).getPrivate());
            var bytes = Base64.getDecoder().decode(keyAccess.wrappedKey);
            try {
                return decryptor.decrypt(bytes);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
            return null;
        }

        @Override
        public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {
            return null;
        }
    };

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @BeforeAll
    static void createKeypairs() {
        for (int i = 0; i < 1 + new Random().nextInt(5); i++) {
            keypairs.add(CryptoUtils.generateRSAKeypair());
        }
    }

    @Test
    void testSimpleTDFEncryptAndDecrypt() throws Exception {
        var assertion1 = new Assertion();
        assertion1.id = "assertion1";
        assertion1.type = Assertion.Type.HandlingAssertion.toString();
        assertion1.scope = Assertion.Scope.TrustedDataObj.toString();
        assertion1.appliesToState = Assertion.AppliesToState.Unencrypted.toString();
        assertion1.statement = new Assertion.Statement();
        assertion1.statement.format = Assertion.StatementFormat.Base64BinaryStatement.toString();
        assertion1.statement.value = "ICAgIDxlZGoOkVkaD4=";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withMetaData("here is some metadata"),
                Config.WithAssertion(assertion1)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), new Config.AssertionConfig(), kas);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo("application/octet-stream");

        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
        assertThat(reader.getMetadata()).isEqualTo("here is some metadata");
    }

    @Test
    void testSimpleTDFWithAssertionWithRS256() throws Exception {

        var assertion = new Assertion();
        assertion.id = "assertion1";
        assertion.type = Assertion.Type.HandlingAssertion.name();
        assertion.scope = Assertion.Scope.TrustedDataObj.name();
        assertion.appliesToState = Assertion.AppliesToState.Unencrypted.name();
        assertion.statement = new Assertion.Statement();
        assertion.statement.format = Assertion.StatementFormat.Base64BinaryStatement.name();
        assertion.statement.value = "ICAgIDxlZGoOkVkaD4=";

        var keypair = CryptoUtils.generateRSAKeypair();
        Config.AssertionConfig assertionConfig = new Config.AssertionConfig();
        assertionConfig.keyType = Config.AssertionConfig.KeyType.RS256;
        assertionConfig.rs256PrivateKeyForSigning = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).privateKey(keypair.getPrivate()).build();
        assertionConfig.rs256PublicKeyForVerifying = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).build();

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.WithAssertion(assertion),
                Config.withAssertionConfig(assertionConfig),
                Config.withDisableEncryption()
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), assertionConfig, kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Test
    void testSimpleTDFWithAssertionWithHS256() throws Exception {

        var assertion = new Assertion();
        assertion.id = "assertion1";
        assertion.type = Assertion.Type.HandlingAssertion.name();
        assertion.scope = Assertion.Scope.TrustedDataObj.name();
        assertion.appliesToState = Assertion.AppliesToState.Unencrypted.name();
        assertion.statement = new Assertion.Statement();
        assertion.statement.format = Assertion.StatementFormat.Base64BinaryStatement.name();
        assertion.statement.value = "ICAgIDxlZGoOkVkaD4=";

        Config.AssertionConfig assertionConfig = new Config.AssertionConfig();
        assertionConfig.keyType = Config.AssertionConfig.KeyType.HS256PayloadKey;

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.WithAssertion(assertion),
                Config.withAssertionConfig(assertionConfig)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), assertionConfig, kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Test
    public void testCreatingTDFWithMultipleSegments() throws Exception {
        var random = new Random();

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                // use a random segment size that makes sure that we will use multiple segments
                Config.withSegmentSize(1 + random.nextInt(20))
        );

        // data should be bigger than the largest segment
        var data = new byte[21 + random.nextInt(2048)];
        random.nextBytes(data);
        var plainTextInputStream = new ByteArrayInputStream(data);
        var tdfOutputStream = new ByteArrayOutputStream();
        var tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);
        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()),
                new Config.AssertionConfig(), kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toByteArray())
                .withFailMessage("extracted data does not match")
                .containsExactly(data);

    }

    @Test
    public void testCreatingTooLargeTDF() {
        var random = new Random();
        var maxSize = random.nextInt(1024);
        var numReturned = new AtomicInteger(0);

        // return 1 more byte than the maximum size
        var is = new InputStream() {
            @Override
            public int read() {
                if (numReturned.get() > maxSize) {
                    return -1;
                }
                numReturned.incrementAndGet();
                return 1;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                var numToReturn = Math.min(len, maxSize - numReturned.get() + 1);
                numReturned.addAndGet(numToReturn);
                return numToReturn;
            }
        };

        var os = new OutputStream() {
            @Override
            public void write(int b) {}
            @Override
            public void write(byte[] b, int off, int len) {}
        };

        var tdf = new TDF(maxSize);
        var tdfConfig = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withSegmentSize(1 + random.nextInt(128)));
        assertThrows(TDF.DataSizeNotSupported.class,
                () -> tdf.createTDF(is, os, tdfConfig, kas),
                "didn't throw an exception when we created TDF that was too large");
        assertThat(numReturned.get())
                .withFailMessage("test returned the wrong number of bytes")
                .isEqualTo(maxSize + 1);
    }

    @Test
    public void testCreateTDFWithMimeType() throws Exception {

        final String mimeType = "application/pdf";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withMimeType(mimeType)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), new Config.AssertionConfig(), kas);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo(mimeType);
    }

    @Nonnull
    private static Config.KASInfo[] getKASInfos() {
        var kasInfos = new ArrayList<>();
        for (int i = 0; i < keypairs.size(); i++) {
            var kasInfo = new Config.KASInfo();
            kasInfo.URL = Integer.toString(i);
            kasInfo.PublicKey = null;
            kasInfos.add(kasInfo);
        }
        return kasInfos.toArray(Config.KASInfo[]::new);
    }
}
