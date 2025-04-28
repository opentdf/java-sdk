package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;
import io.opentdf.platform.generated.policy.KeyAccessServer;
import io.opentdf.platform.generated.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.generated.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.generated.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.Config.NanoTDFReaderConfig;
import io.opentdf.platform.sdk.nanotdf.ECKeyPair;
import io.opentdf.platform.sdk.nanotdf.Header;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import java.nio.charset.StandardCharsets;
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

    private static final String KID = "r1";

    protected static KeyAccessServerRegistryServiceClient kasRegistryService;
    protected static List<String> registeredKases = List.of(
            "https://api.example.com/kas",
            "https://other.org/kas2",
            "http://localhost:8181/kas",
            "https://localhost:8383/kas"
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
            if (kasInfo.Algorithm != null && !"ec:secp256r1".equals(kasInfo.Algorithm)) {
                throw new IllegalArgumentException("Unexpected algorithm: " + kasInfo);
            }
            var k2 = kasInfo.clone();
            k2.KID = KID;
            k2.PublicKey = kasPublicKey;
            return k2;
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {
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
        public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {

            byte[] headerAsBytes = Base64.getDecoder().decode(header);
            Header nTDFHeader = new Header(ByteBuffer.wrap(headerAsBytes));
            byte[] ephemeralKey = nTDFHeader.getEphemeralKey();

            String publicKeyAsPem = ECKeyPair.publicKeyFromECPoint(ephemeralKey, nTDFHeader.getECCMode().getCurveName());

            // Generate symmetric key
            byte[] symmetricKey = ECKeyPair.computeECDHKey(ECKeyPair.publicKeyFromPem(publicKeyAsPem),
                    ECKeyPair.privateKeyFromPem(kasPrivateKey));

            // Generate HKDF key
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("error creating SHA-256 message digest", e);
            }
            byte[] hashOfSalt = digest.digest(NanoTDF.MAGIC_NUMBER_AND_VERSION);
            byte[] key = ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);
            return key;
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
                    }
                });
//        io.grpc.Channel mockChannel = mock(io.grpc.Channel.class);
//        when(mockChannel.authority()).thenReturn("mock:8080");
//        when(kasRegistryService.getChannel()).thenReturn(mockChannel);
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
                Config.witDataAttributes("https://example.com/attr/Classification/value/S",
                        "https://example.com/attr/Classification/value/X")
        );

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF nanoTDF = new NanoTDF();
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, config, kas);

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        nanoTDF = new NanoTDF();
        nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, kas, kasRegistryService, platformUrl);

        String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(out).isEqualTo(plainText);
        // KAS KID
        assertThat(new String(nanoTDFBytes, StandardCharsets.UTF_8)).contains(KID);
        

        int[] nanoTDFSize = { 0, 1, 100*1024, 1024*1024, 4*1024*1024, 12*1024*1024, 15*1024,1024, ((16 * 1024 * 1024) - 3 - 32) };
        for (int size: nanoTDFSize) {
            byte[] data = new byte[size];
            new Random().nextBytes(data);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            NanoTDF nTDF = new NanoTDF();
            nTDF.createNanoTDF(ByteBuffer.wrap(data), outputStream, config, kas);

            byte[] nTDFBytes = outputStream.toByteArray();
            ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
            nanoTDF.readNanoTDF(ByteBuffer.wrap(nTDFBytes), dataStream, kas, kasRegistryService, platformUrl);
            assertThat(dataStream.toByteArray()).isEqualTo(data);
        }
    }

    void runBasicTest(String kasUrl, boolean allowed, KeyAccessServerRegistryServiceClient kasReg, NanoTDFReaderConfig decryptConfig) throws Exception {
        var kasInfos = new ArrayList<>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = kasUrl;
        kasInfo.PublicKey = null;
        kasInfos.add(kasInfo);

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                Config.witDataAttributes("https://example.com/attr/Classification/value/S",
                        "https://example.com/attr/Classification/value/X")
        );

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF nanoTDF = new NanoTDF();
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, config, kas);

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        nanoTDF = new NanoTDF();
        if (allowed) {
            if (decryptConfig != null) {
                nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, kas, decryptConfig);
            } else {
                nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, kas, kasReg, platformUrl);
            }
            String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
            assertThat(out).isEqualTo(plainText);
        } else {
            try {
                if (decryptConfig != null) {
                    nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, kas, decryptConfig);
                } else {
                    nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, kas, kasReg, platformUrl);
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
            runBasicTest(kasUrl, true, kasRegistryService, null);
        }
        for (String kasUrl : kasUrlsFail) {
            runBasicTest(kasUrl, false, kasRegistryService, null);
        } 
        
        // test with kasAllowlist
        runBasicTest("http://api.example.com/kas", true, null, Config.newNanoTDFReaderConfig(Config.WithNanoKasAllowlist("http://api.example.com/kas")));
        runBasicTest(platformUrl+"/kas", false, null, Config.newNanoTDFReaderConfig(Config.WithNanoKasAllowlist("http://api.example.com/kas")));

        // test ignore kasAllowlist
        runBasicTest(platformUrl+"/kas", true, null, Config.newNanoTDFReaderConfig(Config.WithNanoKasAllowlist("http://api.example.com/kas"), Config.WithNanoIgnoreKasAllowlist(true)));
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

        NanoTDF nanoTDF = new NanoTDF();
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

    private ByteBuffer getHeaderBuffer(ByteBuffer input, NanoTDF nanoTDF, Config.NanoTDFConfig config) throws Exception {
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();
        nanoTDF.createNanoTDF(input, tdfOutputStream, config, kas);
        ByteBuffer tdf = ByteBuffer.wrap(tdfOutputStream.toByteArray());
        Header header = new Header(tdf);
        return tdf.position(0).slice().limit(header.getTotalSize());
    }
}
