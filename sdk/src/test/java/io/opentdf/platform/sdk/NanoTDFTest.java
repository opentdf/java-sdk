package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.Config.NanoTDFReaderConfig;

import java.nio.charset.StandardCharsets;

import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Random;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class NanoTDFTest {

    public static final String kasPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC4Wmdb7smRiIeA/Zkua2TNj9kySE\n" +
            "8Q2MaJ0kQX9GFePqi5KNDVnjBxQrkHXSTGB7Z/SrRny9vxgo86FT+1aXMQ==\n" +
            "-----END PUBLIC KEY-----";

    public static final String kasPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
            "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2Wgo3sPikn/fj9uU\n" +
            "/cU+F4I2rRyOit9/s3fNjHVLxgugCgYIKoZIzj0DAQehRANCAAQLhaZ1vuyZGIh4\n" +
            "D9mS5rZM2P2TJITxDYxonSRBf0YV4+qLko0NWeMHFCuQddJMYHtn9KtGfL2/GCjz\n" +
            "oVP7Vpcx\n" +
            "-----END PRIVATE KEY-----";

    private static final String BASE_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/NawR/F7RJfX/odyOLPjl+5Ce1Br\n" +
            "QZ/MBCIerHe26HzlBSbpa7HQHZx9PYVamHTw9+iJCY3dm8Uwp4Ab2uehnA==\n" +
            "-----END PUBLIC KEY-----";

    private static final String BASE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgB3YtAvS7lctHlPsq\n" +
            "bZI8OX1B9W1c4GAIxzwKzD6iPkqhRANCAAT81rBH8XtEl9f+h3I4s+OX7kJ7UGtB\n" +
            "n8wEIh6sd7bofOUFJulrsdAdnH09hVqYdPD36IkJjd2bxTCngBva56Gc\n" +
            "-----END PRIVATE KEY-----" ;

    private static final String KID = "r1";
    private static final String BASE_KID = "basekid";

    protected static KeyAccessServerRegistryServiceClient kasRegistryService;
    protected static List<String> registeredKases = List.of(
            "https://api.example.com/kas",
            "https://other.org/kas2",
            "http://localhost:8181/kas",
            "https://localhost:8383/kas",
            "https://api.kaswithbasekey.example.com"
    );
    protected static String platformUrl = "http://localhost:8080";
    
    protected static SDK.KAS kas = new SDK.KAS() {
        @Override
        public void close() throws Exception {
        }

        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            Config.KASInfo returnKI = new Config.KASInfo();
            returnKI.PublicKey = kasPublicKey;
            return returnKI;
        }

        @Override
        public KASInfo getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
            var k2 = kasInfo.clone();
            if (Objects.equals(kasInfo.KID, BASE_KID)) {
                assertThat(kasInfo.URL).isEqualTo("https://api.kaswithbasekey.example.com");
                assertThat(kasInfo.Algorithm).isEqualTo("ec:secp384r1");
                k2.PublicKey = BASE_PUBLIC_KEY;
                return k2;
            }
            if (kasInfo.Algorithm != null && !"ec:secp256r1".equals(kasInfo.Algorithm)) {
                throw new IllegalArgumentException("Unexpected algorithm: " + kasInfo);
            }
            k2.KID = KID;
            k2.PublicKey = kasPublicKey;
            k2.Algorithm = "ec:secp256r1";
            return k2;
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {
            throw new UnsupportedOperationException("no unwrapping ZTDFs here");
        }

        @Override
        public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {
            String key = Objects.equals(kasURL, "https://api.kaswithbasekey.example.com")
                    ? BASE_PRIVATE_KEY
                    : kasPrivateKey;
            byte[] headerAsBytes = Base64.getDecoder().decode(header);
            Header nTDFHeader = new Header(ByteBuffer.wrap(headerAsBytes));
            byte[] ephemeralKey = nTDFHeader.getEphemeralKey();

            String publicKeyAsPem = ECKeyPair.publicKeyFromECPoint(ephemeralKey, nTDFHeader.getECCMode().getCurve().getCurveName());

            // Generate symmetric key
            byte[] symmetricKey = ECKeyPair.computeECDHKey(ECKeyPair.publicKeyFromPem(publicKeyAsPem),
                    ECKeyPair.privateKeyFromPem(key));

            // Generate HKDF key
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("error creating SHA-256 message digest", e);
            }
            byte[] hashOfSalt = digest.digest(NanoTDF.MAGIC_NUMBER_AND_VERSION);
            return ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);
        }

        @Override
        public KASKeyCache getKeyCache(){
            return new KASKeyCache();
        }
    };

    @BeforeAll
    static void setupMocks() {
        kasRegistryService = mock(KeyAccessServerRegistryServiceClient.class);
        List<KeyAccessServer> kasRegEntries = new ArrayList<>();
        for (String kasUrl : registeredKases ) {
            kasRegEntries.add(KeyAccessServer.newBuilder()
                        .setUri(kasUrl).build());
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

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @Test
    void encryptionAndDecryptionWithValidKey() throws Exception {
        var kasInfos = new ArrayList<>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "https://api.example.com/kas";
        kasInfo.PublicKey = null;
        kasInfo.KID = KID;
        kasInfos.add(kasInfo);

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                Config.withEllipticCurve("secp384r1"),
                Config.witDataAttributes("https://example.com/attr/Classification/value/S",
                        "https://example.com/attr/Classification/value/X")
        );

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, config);

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, platformUrl);

        String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(out).isEqualTo(plainText);
        // KAS KID
        assertThat(new String(nanoTDFBytes, StandardCharsets.UTF_8)).contains(KID);
        

        int[] nanoTDFSize = { 0, 1, 100*1024, 1024*1024, 4*1024*1024, 12*1024*1024, 15*1024,1024, ((16 * 1024 * 1024) - 3 - 32) };
        for (int size: nanoTDFSize) {
            byte[] data = new byte[size];
            new Random().nextBytes(data);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            NanoTDF nTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
            nTDF.createNanoTDF(ByteBuffer.wrap(data), outputStream, config);

            byte[] nTDFBytes = outputStream.toByteArray();
            ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
            nanoTDF.readNanoTDF(ByteBuffer.wrap(nTDFBytes), dataStream, platformUrl);
            assertThat(dataStream.toByteArray()).isEqualTo(data);
        }
    }

    @Test
    void encryptionAndDecryptWithBaseKey() throws Exception {
        var baseKeyJson = "{\"kas_url\":\"https://api.kaswithbasekey.example.com\",\"public_key\":{\"algorithm\":\"ALGORITHM_EC_P256\",\"kid\":\"" + BASE_KID  + "\",\"pem\": \"" + BASE_PUBLIC_KEY +  "\"}}";
        var val = Value.newBuilder().setStringValue(baseKeyJson).build();
        var config = Struct.newBuilder().putFields("base_key", val).build();
        WellKnownServiceClientInterface wellknown = mock(WellKnownServiceClientInterface.class);
        GetWellKnownConfigurationResponse response = GetWellKnownConfigurationResponse.newBuilder().setConfiguration(config).build();
        when(wellknown.getWellKnownConfigurationBlocking(any(), any())).thenReturn(TestUtil.successfulUnaryCall(response));
        Config.NanoTDFConfig nanoConfig = Config.newNanoTDFConfig(
                Config.witDataAttributes("https://example.com/attr/Classification/value/S",
                        "https://example.com/attr/Classification/value/X")
        );

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();
        NanoTDF nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).setWellknownService(wellknown).build());
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, nanoConfig);

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, platformUrl);
        String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(out).isEqualTo(plainText);
        // KAS KID
        assertThat(new String(nanoTDFBytes, StandardCharsets.UTF_8)).contains(BASE_KID);
    }

    @Test
    void testWithDifferentConfigAndKeyValues() throws Exception {
        var kasInfos = new ArrayList<>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "https://api.example.com/kas";
        kasInfo.PublicKey = null;
        kasInfos.add(kasInfo);
        var config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                Config.withEllipticCurve("secp384r1"),
                Config.witDataAttributes("https://example.com/attr/Classification/value/S", "https://example.com/attr/Classification/value/X")
        );
        runBasicTest(null, true, kasRegistryService, null, config);
    }

    void runBasicTest(String kasUrl, boolean allowed, KeyAccessServerRegistryServiceClient kasReg, NanoTDFReaderConfig decryptConfig, Config.NanoTDFConfig writerConfig) throws Exception {
        Config.NanoTDFConfig config;
        if (writerConfig == null) {
            var kasInfos = new ArrayList<>();
            var kasInfo = new Config.KASInfo();
            kasInfo.URL = kasUrl;
            kasInfo.PublicKey = null;
            kasInfos.add(kasInfo);
            config = Config.newNanoTDFConfig(
                    Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                    Config.witDataAttributes("https://example.com/attr/Classification/value/S", "https://example.com/attr/Classification/value/X")
            );
        } else {
            config = writerConfig;
        }

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasReg).build());
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, config);

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasReg).build());
        if (allowed) {
            if (decryptConfig != null) {
                nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, decryptConfig);
            } else {
                nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, platformUrl);
            }
            String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
            assertThat(out).isEqualTo(plainText);
        } else {
            try {
                if (decryptConfig != null) {
                    nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, decryptConfig);
                } else {
                    nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, platformUrl);
                }
                assertThat(false).isTrue();
            } catch (SDKException e) {
                assertThat(e.getMessage()).contains("KasAllowlist");
            }
        }
    }

    @Test
    void kasAllowlistTests() throws Exception {
        var kasUrlsSuccess = List.of(
                "https://api.example.com/kas",
                "https://other.org/kas2",
                "http://localhost:8181/kas",
                "https://localhost:8383/kas",
                platformUrl+"/kas"
        );
        var kasUrlsFail = List.of(
                "http://api.example.com/kas",
                "http://other.org/kas",
                "https://localhost:8181/kas2",
                "https://localhost:8282/kas2",
                "https://localhost:8080/kas"
        );
        for (String kasUrl : kasUrlsSuccess) {
            runBasicTest(kasUrl, true, kasRegistryService, null, null);
        }
        for (String kasUrl : kasUrlsFail) {
            runBasicTest(kasUrl, false, kasRegistryService, null, null);
        } 
        
        // test with kasAllowlist
        runBasicTest("http://api.example.com/kas", true, null, Config.newNanoTDFReaderConfig(Config.WithNanoKasAllowlist("http://api.example.com/kas")), null);
        runBasicTest(platformUrl+"/kas", false, null, Config.newNanoTDFReaderConfig(Config.WithNanoKasAllowlist("http://api.example.com/kas")), null);

        // test ignore kasAllowlist
        runBasicTest(platformUrl+"/kas", true, null, Config.newNanoTDFReaderConfig(Config.WithNanoKasAllowlist("http://api.example.com/kas"), Config.WithNanoIgnoreKasAllowlist(true)), null);
    }

    @Test
    void collection() throws Exception {
        var kasInfos = new ArrayList<>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "https://api.example.com/kas";
        kasInfo.PublicKey = null;
        kasInfo.KID = KID;
        kasInfos.add(kasInfo);

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                Config.witDataAttributes("https://example.com/attr/Classification/value/S",
                        "https://example.com/attr/Classification/value/X"),
                Config.withCollection()
        );

        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[]{});

        NanoTDF nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).build());
        ByteBuffer header = getHeaderBuffer(byteBuffer,nanoTDF, config);
        for (int i = 0; i < Config.MAX_COLLECTION_ITERATION - 10; i++) {
            config.collectionConfig.getHeaderInfo();

        }
        for (int i = 1; i < 10; i++) {
            ByteBuffer newHeader = getHeaderBuffer(byteBuffer,nanoTDF, config);
            assertThat(header).isEqualTo(newHeader);
        }

        ByteBuffer newHeader = getHeaderBuffer(byteBuffer,nanoTDF, config);
        assertThat(header).isNotEqualTo(newHeader);
    }

    @Test
    public void testNanoTDFWithPlainTextPolicy() throws Exception {
        List<String> sampleAttributes = List.of("https://example.com/attr/Classification/value/S");
        String sampleKasUrl = "https://api.example.com/kas";
        byte[] sampleData = "test-policy".getBytes(StandardCharsets.UTF_8);

        var kasInfos = new ArrayList<Config.KASInfo>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = sampleKasUrl;
        kasInfo.PublicKey = kasPublicKey;
        kasInfo.KID = KID;
        kasInfo.Algorithm = "ec:secp256r1";
        kasInfos.add(kasInfo);

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                Config.witDataAttributes(sampleAttributes.toArray(new String[0])),
                Config.withPolicyType(NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT)
        );

        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();
        NanoTDF nanoTDF = new NanoTDF(new FakeServicesBuilder().setKas(kas).setKeyAccessServerRegistryService(kasRegistryService).build());
        nanoTDF.createNanoTDF(ByteBuffer.wrap(sampleData), tdfOutputStream, config);

        byte[] tdfData = tdfOutputStream.toByteArray();
        Header header = new Header(ByteBuffer.wrap(tdfData));
        String policyJson = new String(header.getPolicyInfo().getEmbeddedPlainTextPolicy(), StandardCharsets.UTF_8);

        assertThat(policyJson)
                .as("Policy JSON should contain the expected attribute")
                .contains(sampleAttributes.get(0));
    }

    private ByteBuffer getHeaderBuffer(ByteBuffer input, NanoTDF nanoTDF, Config.NanoTDFConfig config) throws Exception {
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();
        nanoTDF.createNanoTDF(input, tdfOutputStream, config);
        ByteBuffer tdf = ByteBuffer.wrap(tdfOutputStream.toByteArray());
        Header header = new Header(tdf);
        return tdf.position(0).slice().limit(header.getTotalSize());
    }
}
