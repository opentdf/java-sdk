package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;
import com.nimbusds.jose.JOSEException;
import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.TDF.Reader;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.opentdf.platform.sdk.TDF.GLOBAL_KEY_SALT;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TDFTest {
    protected static KeyAccessServerRegistryServiceClient kasRegistryService;
    protected static String platformUrl = "http://localhost:8080";

    protected static SDK.KAS kas = new SDK.KAS() {
        @Override
        public void close() {
        }

        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            // handle platform url
            int index;
            // if the kasinfo url contains the platform url, remove it
            if (kasInfo.URL.startsWith(platformUrl)) {
                index = Integer.parseInt(kasInfo.URL.replaceFirst("^" + Pattern.quote(platformUrl) + "/kas", ""));
            } else {
                index = Integer.parseInt(kasInfo.URL.replaceFirst("^https://example.com/kas", ""));
            }
            var kiCopy = new Config.KASInfo();
            kiCopy.KID = "r1";
            kiCopy.PublicKey = CryptoUtils.getPublicKeyPEM(keypairs.get(index).getPublic());
            kiCopy.URL = kasInfo.URL;
            return kiCopy;
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {

            try {
                int index;
                // if the keyAccess.url contains the platform url, remove it
                if (keyAccess.url.startsWith(platformUrl)) {
                    index = Integer.parseInt(keyAccess.url.replaceFirst("^" + Pattern.quote(platformUrl) + "/kas", ""));
                } else {
                    index = Integer.parseInt(keyAccess.url.replaceFirst("^https://example.com/kas", ""));
                }
                var bytes = Base64.getDecoder().decode(keyAccess.wrappedKey);
                if (sessionKeyType.isEc()) {
                    var  kasPrivateKey = CryptoUtils.getPrivateKeyPEM(keypairs.get(index).getPrivate());
                    var privateKey = ECKeyPair.privateKeyFromPem(kasPrivateKey);
                    var clientEphemeralPublicKey = keyAccess.ephemeralPublicKey;
                    var publicKey = ECKeyPair.publicKeyFromPem(clientEphemeralPublicKey);
                    byte[] symKey = ECKeyPair.computeECDHKey(publicKey, privateKey);

                    var sessionKey = ECKeyPair.calculateHKDF(GLOBAL_KEY_SALT, symKey);

                    AesGcm gcm = new AesGcm(sessionKey);
                    AesGcm.Encrypted encrypted = new AesGcm.Encrypted(bytes);
                    return gcm.decrypt(encrypted);
                } else {
                    var decryptor = new AsymDecryption(keypairs.get(index).getPrivate());
                    return decryptor.decrypt(bytes);
                }
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
        public KASKeyCache getKeyCache() {
            return new KASKeyCache();
        }
    };

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @BeforeAll
    static void setupKeyPairsAndMocks() {
        for (int i = 0; i < 2 + new Random().nextInt(5); i++) {
            if (i % 2 == 0) {
                keypairs.add(CryptoUtils.generateRSAKeypair());
            } else {
                keypairs.add(CryptoUtils.generateECKeypair(KeyType.EC256Key.getCurveName()));
            }
        }

        kasRegistryService = mock(KeyAccessServerRegistryServiceClient.class);
        List<KeyAccessServer> kasRegEntries = new ArrayList<>();
        for (Config.KASInfo kasInfo : getRSAKASInfos()) {
            kasRegEntries.add(KeyAccessServer.newBuilder()
                        .setUri(kasInfo.URL).build());
        }
        for (Config.KASInfo kasInfo : getECKASInfos()) {
            kasRegEntries.add(KeyAccessServer.newBuilder()
                        .setUri(kasInfo.URL).build());
        }
        ListKeyAccessServersResponse mockResponse = ListKeyAccessServersResponse.newBuilder()
                .addAllKeyAccessServers(kasRegEntries)
                .build();

        // Stub the listKeyAccessServers method
        when(kasRegistryService.listKeyAccessServersBlocking(any(ListKeyAccessServersRequest.class), any()))
                .thenReturn(new UnaryBlockingCall<>() {
                    @Override
                    public ResponseMessage<ListKeyAccessServersResponse> execute() {
                        return new ResponseMessage.Success<>(mockResponse, Collections.emptyMap(), Collections.emptyMap());
                    }

                    @Override
                    public void cancel() {
                        // this never happens in tests
                    }
                });
    }

    @Test
    void testSimpleTDFEncryptAndDecrypt() throws Exception {

        class TDFConfigPair {
            public final Config.TDFConfig tdfConfig;
            public final Config.TDFReaderConfig tdfReaderConfig;

            public TDFConfigPair(Config.TDFConfig tdfConfig, Config.TDFReaderConfig tdfReaderConfig) {
                this.tdfConfig = tdfConfig;
                this.tdfReaderConfig = tdfReaderConfig;
            }
        }

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
        assertion1.signingKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.defaultKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                key);

        List<TDFConfigPair> tdfConfigPairs = List.of(
                new TDFConfigPair(
                        Config.newTDFConfig( Config.withAutoconfigure(false),  Config.withKasInformation(getRSAKASInfos()),
                                Config.withMetaData("here is some metadata"),
                                Config.withDataAttributes("https://example.org/attr/a/value/b", "https://example.org/attr/c/value/d"),
                                Config.withAssertionConfig(assertion1)),
                        Config.newTDFReaderConfig(Config.withAssertionVerificationKeys(assertionVerificationKeys))
                ),
                new TDFConfigPair(
                        Config.newTDFConfig( Config.withAutoconfigure(false),  Config.withKasInformation(getECKASInfos()),
                                Config.withMetaData("here is some metadata"),
                                Config.WithWrappingKeyAlg(KeyType.EC256Key),
                                Config.withDataAttributes("https://example.org/attr/a/value/b", "https://example.org/attr/c/value/d"),
                                Config.withAssertionConfig(assertion1)),
                        Config.newTDFReaderConfig(Config.withAssertionVerificationKeys(assertionVerificationKeys),
                                Config.WithSessionKeyType(KeyType.EC256Key))
                )
        );

        for (TDFConfigPair configPair : tdfConfigPairs) {
            String plainText = "this is extremely sensitive stuff!!!";
            InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
            ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

            TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
            var manifest = tdf.createTDF(plainTextInputStream, tdfOutputStream, configPair.tdfConfig).getManifest();

            assertThat(manifest.assertions).asList().hasSize(1);
            var assertion = manifest.assertions.get(0);
            assertThat(assertion.appliesToState).isEqualTo("unencrypted");
            assertThat(assertion.type).isEqualTo("base");
            assertThat(assertion.statement.value).isEqualTo("ICAgIDxlZGoOkVkaD4=");
            assertThat(assertion.statement.schema).isEqualTo("text");
            assertThat(assertion.statement.format).isEqualTo("base64binary");

            assertThat(manifest.payload.isEncrypted).isTrue();
            var size = manifest.encryptionInformation.integrityInformation.segments.stream().map(s -> s.segmentSize).reduce(0L, Long::sum);
            assertThat(size).isEqualTo(plainText.getBytes().length);

            var unwrappedData = new ByteArrayOutputStream();
            var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), configPair.tdfReaderConfig, platformUrl);
            assertThat(reader.getManifest().payload.mimeType).isEqualTo("application/octet-stream");

            reader.readPayload(unwrappedData);

            assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                    .withFailMessage("extracted data does not match")
                    .isEqualTo(plainText);
            assertThat(reader.getMetadata()).isEqualTo("here is some metadata");

            var policyObject = reader.readPolicyObject();
            assertThat(policyObject).isNotNull();
            assertThat(policyObject.body.dataAttributes.stream().map(a -> a.attribute).collect(Collectors.toList())).asList()
                    .containsExactlyInAnyOrder("https://example.org/attr/a/value/b", "https://example.org/attr/c/value/d");
        }
    }

    @Test
    void testSimpleTDFWithAssertionWithRS256() throws Exception {
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
        assertionConfig.signingKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256,
                keypair.getPrivate());

        var rsaKasInfo = new Config.KASInfo();
        rsaKasInfo.URL = "https://example.com/kas"+ 0;

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(rsaKasInfo),
                Config.withAssertionConfig(assertionConfig));

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.keys.put(assertion1Id,
                new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, keypair.getPublic()));

        var unwrappedData = new ByteArrayOutputStream();
        Config.TDFReaderConfig readerConfig = Config.newTDFReaderConfig(
                Config.withAssertionVerificationKeys(assertionVerificationKeys));
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), readerConfig, platformUrl);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Test
    void testWithAssertionVerificationDisabled() throws Exception {
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
        assertionConfig.signingKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256,
                keypair.getPrivate());

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getRSAKASInfos()),
                Config.withAssertionConfig(assertionConfig));

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.keys.put(assertion1Id,
                new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, keypair.getPublic()));

        var unwrappedData = new ByteArrayOutputStream();
        var dataToUnwrap = new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray());
        var emptyConfig= Config.newTDFReaderConfig();
        var thrown = assertThrows(SDKException.class, () -> {
            tdf.loadTDF(dataToUnwrap, emptyConfig, platformUrl);
        });
        assertThat(thrown.getCause()).isInstanceOf(JOSEException.class);

        //  try with assertion verification disabled and not passing the assertion verification keys
        Config.TDFReaderConfig readerConfig = Config.newTDFReaderConfig(
                Config.withDisableAssertionVerification(true));
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), readerConfig, platformUrl);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }
    @Test
    void testSimpleTDFWithAssertionWithHS256() throws Exception {
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

        var rsaKasInfo = new Config.KASInfo();
        rsaKasInfo.URL = "https://example.com/kas"+ 0;

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(rsaKasInfo),
                Config.withAssertionConfig(assertionConfig1, assertionConfig2));

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), Config.newTDFReaderConfig(), platformUrl);
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
                assertThat(assertion.statement.value).isEqualTo(
                        "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}");
                assertThat(assertion.type).isEqualTo(AssertionConfig.Type.HandlingAssertion.toString());
            } else {
                throw new RuntimeException("unexpected assertion id: " + assertion.id);
            }
        }
    }

    @Test
    void testSimpleTDFWithAssertionWithHS256Failure() throws Exception {
        // var keypair = CryptoUtils.generateRSAKeypair();
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);

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
        assertionConfig1.signingKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);

        var rsaKasInfo = new Config.KASInfo();
        rsaKasInfo.URL = "https://example.com/kas"+ 0;

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(rsaKasInfo),
                Config.withAssertionConfig(assertionConfig1));

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        byte[] notkey = new byte[32];
        secureRandom.nextBytes(notkey);
        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.defaultKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
            notkey);
        Config.TDFReaderConfig readerConfig = Config.newTDFReaderConfig(
            Config.withAssertionVerificationKeys(assertionVerificationKeys));

        try {
            tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), readerConfig, platformUrl);
            throw new RuntimeException("assertion verify key error thrown");

        } catch (SDKException e) {
            assertThat(e).hasMessageContaining("verify");
        }
    }

    @Test
    public void testCreatingTDFWithMultipleSegments() throws Exception {
        var random = new Random();

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getRSAKASInfos()),
                Config.withSegmentSize(Config.MIN_SEGMENT_SIZE));

        // data should be large enough to have multiple complete and a partial segment
        var data = new byte[(int)(Config.MIN_SEGMENT_SIZE * 2.8)];
        random.nextBytes(data);
        var plainTextInputStream = new ByteArrayInputStream(data);
        var tdfOutputStream = new ByteArrayOutputStream();
        var tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);
        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), platformUrl);
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
            public void write(int b) {
            }

            @Override
            public void write(byte[] b, int off, int len) {
            }
        };

        var tdf = new TDF(maxSize, new FakeServicesBuilder().setKas(kas).build());
        var tdfConfig = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getRSAKASInfos()),
                Config.withSegmentSize(Config.MIN_SEGMENT_SIZE));
        assertThrows(SDK.DataSizeNotSupported.class,
                () -> tdf.createTDF(is, os, tdfConfig),
                "didn't throw an exception when we created TDF that was too large");
        assertThat(numReturned.get())
                .withFailMessage("test returned the wrong number of bytes")
                .isEqualTo(maxSize + 1);
    }

    @Test
    public void testCreateTDFWithMimeType() throws Exception {
        final String mimeType = "application/pdf";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getRSAKASInfos()),
                Config.withMimeType(mimeType));

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), platformUrl);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo(mimeType);
    }

    @Test
    void legacyTDFRoundTrips() throws IOException {
        final String mimeType = "application/pdf";
        var assertionConfig1 = new AssertionConfig();
        assertionConfig1.id = "assertion1";
        assertionConfig1.type = AssertionConfig.Type.BaseAssertion;
        assertionConfig1.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig1.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig1.statement = new AssertionConfig.Statement();
        assertionConfig1.statement.format = "base64binary";
        assertionConfig1.statement.schema = "text";
        assertionConfig1.statement.value = "ICAgIDxlZGoOkVkaD4=";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(getRSAKASInfos()),
                Config.withTargetMode("4.2.1"),
                Config.withAssertionConfig(assertionConfig1),
                Config.withMimeType(mimeType));

        byte[] data = new byte[129];
        new Random().nextBytes(data);
        InputStream plainTextInputStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        var dataOutputStream = new ByteArrayOutputStream();

        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), platformUrl);
        var integrityInformation = reader.getManifest().encryptionInformation.integrityInformation;
        assertThat(reader.getManifest().tdfVersion).isNull();
        var decodedSignature = Base64.getDecoder().decode(integrityInformation.rootSignature.signature);
        for (var b: decodedSignature) {
            assertThat(isHexChar(b))
                    .withFailMessage("non-hex byte in signature: " + b)
                    .isTrue();
        }
        for (var s: integrityInformation.segments) {
            var decodedSegmentSignature = Base64.getDecoder().decode(s.hash);
            for (var b: decodedSegmentSignature) {
                assertThat(isHexChar(b))
                        .withFailMessage("non-hex byte in segment signature: " + b)
                        .isTrue();
            }
        }
        reader.readPayload(dataOutputStream);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo(mimeType);
        assertArrayEquals(data, dataOutputStream.toByteArray(), "extracted data does not match");
        var manifest = reader.getManifest();
        var assertions = manifest.assertions;
        assertThat(assertions.size()).isEqualTo(1);
        var assertion = assertions.get(0);
        assertThat(assertion.id).isEqualTo("assertion1");
        assertThat(assertion.statement.format).isEqualTo("base64binary");
        assertThat(assertion.statement.schema).isEqualTo("text");
        assertThat(assertion.statement.value).isEqualTo("ICAgIDxlZGoOkVkaD4=");
        assertThat(assertion.type).isEqualTo(AssertionConfig.Type.BaseAssertion.toString());
    }

    @Test
    void testKasAllowlist() throws Exception {

        KeyAccessServerRegistryServiceClient kasRegistryServiceNoUrl = mock(KeyAccessServerRegistryServiceClient.class);
        List<KeyAccessServer> kasRegEntries = new ArrayList<>();
        kasRegEntries.add(KeyAccessServer.newBuilder()
        .setUri("http://example.com/kas0").build());

        ListKeyAccessServersResponse mockResponse = ListKeyAccessServersResponse.newBuilder()
                .addAllKeyAccessServers(kasRegEntries)
                .build();

        // Stub the listKeyAccessServers method
        when(kasRegistryServiceNoUrl.listKeyAccessServersBlocking(any(ListKeyAccessServersRequest.class), any()))
                .thenReturn(new UnaryBlockingCall<>() {
                                @Override
                                public ResponseMessage<ListKeyAccessServersResponse> execute() {
                                    return new ResponseMessage.Success<>(mockResponse, Collections.emptyMap(), Collections.emptyMap());
                                }

                                @Override
                                public void cancel() {
                                    // we never do this during tests
                                }
                            }
                );

        var rsaKasInfo = new Config.KASInfo();
        rsaKasInfo.URL = "https://example.com/kas"+Integer.toString(0);

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(rsaKasInfo));

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryServiceNoUrl).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        var unwrappedData = new ByteArrayOutputStream();

        // should throw error because the kas url is not in the allowlist
        try {
            tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), Config.newTDFReaderConfig(), platformUrl);
            throw new RuntimeException("expected allowlist error to be thrown");
        } catch (Exception e) {
            assertThat(e).hasMessageContaining("KasAllowlist");
        }

        // with custom allowlist should succeed
        Config.TDFReaderConfig readerConfig = Config.newTDFReaderConfig(
            Config.WithKasAllowlist("https://example.com"));
        tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), readerConfig, platformUrl);

        // with ignore allowlist should succeed
        readerConfig = Config.newTDFReaderConfig(
            Config.WithIgnoreKasAllowlist(true));
        Reader reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), readerConfig, platformUrl);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);


        // use the platform url as kas url, should succeed
        var platformKasInfo = new Config.KASInfo();
        platformKasInfo.URL = platformUrl+"/kas"+Integer.toString(0);
        config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(platformKasInfo));
        plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        tdfOutputStream = new ByteArrayOutputStream();
        tdf = new TDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryServiceNoUrl).build());
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config);

        unwrappedData = new ByteArrayOutputStream();
        reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), Config.newTDFReaderConfig(), platformUrl);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Nonnull
    private static Config.KASInfo[] getKASInfos(Predicate<Integer> filter) {
        var kasInfos = new ArrayList<Config.KASInfo>();
        for (int i = 0; i < keypairs.size(); i++) {
            if (filter.test(i)) {
                var kasInfo = new Config.KASInfo();
                kasInfo.URL = "https://example.com/kas"+Integer.toString(i);
                kasInfo.PublicKey = null;
                kasInfos.add(kasInfo);
            }
        }
        return kasInfos.toArray(Config.KASInfo[]::new);
    }

    @Nonnull
    private static Config.KASInfo[] getRSAKASInfos() {
        return getKASInfos(i -> i % 2 == 0);
    }

    @Nonnull
    private static Config.KASInfo[] getECKASInfos() {
        return getKASInfos(i -> i % 2 != 0);
    }

    private static boolean isHexChar(byte b) {
        return (b >= 'a' && b <= 'f') || (b >= '0' && b <= '9');
    }
}
