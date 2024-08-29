package io.opentdf.platform.sdk;


import com.google.common.util.concurrent.ListenableFuture;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;

import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc.AttributesServiceFutureStub;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TDFTest {

    @BeforeEach
    public void setup() {
        attributeGrpcStub = mock(AttributesServiceGrpc.AttributesServiceFutureStub.class);
    }

    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public void close() {}

        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            int index = Integer.parseInt(kasInfo.URL);
            var kiCopy = new Config.KASInfo();
            kiCopy.KID = "r1";
            kiCopy.PublicKey = CryptoUtils.getRSAPublicKeyPEM(keypairs.get(index).getPublic());
            kiCopy.URL = kasInfo.URL;
            return kiCopy;
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
        public KASInfo getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
            return null;
        }

        @Override
        public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {
            return null;
        }

        @Override
        public KASKeyCache getKeyCache(){
            return new KASKeyCache();
        }
    };

    AttributesServiceGrpc.AttributesServiceFutureStub attributeGrpcStub;
    
    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @BeforeAll
    static void createKeypairs() {
        for (int i = 0; i < 1 + new Random().nextInt(5); i++) {
            keypairs.add(CryptoUtils.generateRSAKeypair());
        }
    }

    @Test
    void testSimpleTDFEncryptAndDecrypt() throws Exception {

        ListenableFuture<GetAttributeValuesByFqnsResponse> resp1 = mock(ListenableFuture.class);
        lenient().when(resp1.get()).thenReturn(GetAttributeValuesByFqnsResponse.newBuilder().build());
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class))).thenReturn(resp1);

        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);

        var assertion1 = new AssertionConfig();
        assertion1.id = "assertion1";
        assertion1.type = AssertionConfig.Type.BaseAssertion;
        assertion1.scope = AssertionConfig.Scope.TrustedDataObj;
        assertion1.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertion1.statement = new AssertionConfig.Statement();
        assertion1.statement.format = "base64binary";
        assertion1.statement.schema = "text";
        assertion1.statement.value = "ICAgIDxlZGoOkVkaD4=";
        assertion1.assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getKASInfos()),
                Config.withMetaData("here is some metadata"),
                Config.withAssertionConfig(assertion1)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas, attributeGrpcStub);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.defaultKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas, assertionVerificationKeys);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo("application/octet-stream");

        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
        assertThat(reader.getMetadata()).isEqualTo("here is some metadata");
    }

    @Test
    void testSimpleTDFWithAssertionWithRS256() throws Exception {

        ListenableFuture<GetAttributeValuesByFqnsResponse> resp1 = mock(ListenableFuture.class);
        lenient().when(resp1.get()).thenReturn(GetAttributeValuesByFqnsResponse.newBuilder().build());
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class))).thenReturn(resp1);

        String assertion1Id = "assertion1";
        var keypair = CryptoUtils.generateRSAKeypair();
        var assertionConfig = new AssertionConfig();
        assertionConfig.id = assertion1Id;
        assertionConfig.type = AssertionConfig.Type.BaseAssertion;
        assertionConfig.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig.statement = new AssertionConfig.Statement();
        assertionConfig.statement.format = "base64binary";
        assertionConfig.statement.schema = "text";
        assertionConfig.statement.value = "ICAgIDxlZGoOkVkaD4=";
        assertionConfig.assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256,
                keypair.getPrivate());

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getKASInfos()),
                Config.withAssertionConfig(assertionConfig)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas, attributeGrpcStub);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.keys.put(assertion1Id,
                new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, keypair.getPublic()));

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas, assertionVerificationKeys);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Test
    void testSimpleTDFWithAssertionWithHS256() throws Exception {

        ListenableFuture<GetAttributeValuesByFqnsResponse> resp1 = mock(ListenableFuture.class);
        lenient().when(resp1.get()).thenReturn(GetAttributeValuesByFqnsResponse.newBuilder().build());
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class))).thenReturn(resp1);

        String assertion1Id = "assertion1";
        var assertionConfig1 = new AssertionConfig();
        assertionConfig1.id = assertion1Id;
        assertionConfig1.type = AssertionConfig.Type.BaseAssertion;
        assertionConfig1.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig1.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig1.statement = new AssertionConfig.Statement();
        assertionConfig1.statement.format = "base64binary";
        assertionConfig1.statement.schema = "text";
        assertionConfig1.statement.value = "ICAgIDxlZGoOkVkaD4=";

        String assertion2Id = "assertion2";
        var assertionConfig2 = new AssertionConfig();
        assertionConfig2.id = assertion2Id;
        assertionConfig2.type = AssertionConfig.Type.HandlingAssertion;
        assertionConfig2.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig2.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig2.statement = new AssertionConfig.Statement();
        assertionConfig2.statement.format = "json";
        assertionConfig2.statement.schema = "urn:nato:stanag:5636:A:1:elements:json";
        assertionConfig2.statement.value = "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getKASInfos()),
                Config.withAssertionConfig(assertionConfig1, assertionConfig2)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas, attributeGrpcStub);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);

        var manifest = reader.getManifest();
        var assertions = manifest.assertions;
        assertThat(assertions.size()).isEqualTo(2);
        for (var assertion : assertions) {
            if (assertion.id.equals(assertion1Id)) {
                assertThat(assertion.statement.format).isEqualTo("base64binary");
                assertThat(assertion.statement.schema).isEqualTo("text");
                assertThat(assertion.statement.value).isEqualTo("ICAgIDxlZGoOkVkaD4=");
                assertThat(assertion.type).isEqualTo(AssertionConfig.Type.BaseAssertion.toString());
            } else if (assertion.id.equals(assertion2Id)) {
                assertThat(assertion.statement.format).isEqualTo("json");
                assertThat(assertion.statement.schema).isEqualTo("urn:nato:stanag:5636:A:1:elements:json");
                assertThat(assertion.statement.value).isEqualTo("{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}");
                assertThat(assertion.type).isEqualTo(AssertionConfig.Type.HandlingAssertion.toString());
            } else {
                throw new RuntimeException("unexpected assertion id: " + assertion.id);
            }
        }
    }

    @Test
    public void testCreatingTDFWithMultipleSegments() throws Exception {

        ListenableFuture<GetAttributeValuesByFqnsResponse> resp1 = mock(ListenableFuture.class);
        lenient().when(resp1.get()).thenReturn(GetAttributeValuesByFqnsResponse.newBuilder().build());
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class))).thenReturn(resp1);

        var random = new Random();

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
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
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas, attributeGrpcStub);
        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toByteArray())
                .withFailMessage("extracted data does not match")
                .containsExactly(data);

    }

    @Test
    public void testCreatingTooLargeTDF() throws Exception {
        ListenableFuture<GetAttributeValuesByFqnsResponse> resp1 = mock(ListenableFuture.class);
        lenient().when(resp1.get()).thenReturn(GetAttributeValuesByFqnsResponse.newBuilder().build());
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class))).thenReturn(resp1);


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
                Config.withAutoconfigure(false),
                Config.withKasInformation(getKASInfos()),
                Config.withSegmentSize(1 + random.nextInt(128)));
        assertThrows(TDF.DataSizeNotSupported.class,
                () -> tdf.createTDF(is, os, tdfConfig, kas, attributeGrpcStub),
                "didn't throw an exception when we created TDF that was too large");
        assertThat(numReturned.get())
                .withFailMessage("test returned the wrong number of bytes")
                .isEqualTo(maxSize + 1);
    }

    @Test
    public void testCreateTDFWithMimeType() throws Exception {

        ListenableFuture<GetAttributeValuesByFqnsResponse> resp1 = mock(ListenableFuture.class);
        lenient().when(resp1.get()).thenReturn(GetAttributeValuesByFqnsResponse.newBuilder().build());
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class))).thenReturn(resp1);

        final String mimeType = "application/pdf";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getKASInfos()),
                Config.withMimeType(mimeType)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas, attributeGrpcStub);

        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas);
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
