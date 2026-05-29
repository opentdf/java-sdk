package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.hybrid.bouncycastle.HybridTestKeys;
import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Lives in package {@code io.opentdf.platform.sdk} so it can construct the
 * package-private {@link TDF} class directly and use {@code FakeServicesBuilder}
 * from the sdk test-jar. Keypair material and unwrap are routed through the
 * {@link HybridKeyWrapProvider} SPI (resolved via {@link HybridKeyWrapResolver})
 * so this test doesn't import BouncyCastle types itself.
 */
class TDFHybridTest {

    private static KeyAccessServerRegistryServiceClient kasRegistryService;

    @BeforeAll
    static void setupMocks() {
        kasRegistryService = mock(KeyAccessServerRegistryServiceClient.class);
        ListKeyAccessServersResponse mockResponse = ListKeyAccessServersResponse.newBuilder()
                .addKeyAccessServers(KeyAccessServer.newBuilder().setUri("https://kas.example.com").build())
                .build();
        when(kasRegistryService.listKeyAccessServersBlocking(any(ListKeyAccessServersRequest.class), any()))
                .thenReturn(new UnaryBlockingCall<>() {
                    @Override
                    public ResponseMessage<ListKeyAccessServersResponse> execute() {
                        return new ResponseMessage.Success<>(mockResponse,
                                Collections.emptyMap(), Collections.emptyMap());
                    }

                    @Override
                    public void cancel() {}
                });
    }

    @Test
    void createKeyAccessWithXWingKey() throws Exception {
        roundTripThroughSPI(KeyType.HybridXWingKey, "xwing-kid");
    }

    @Test
    void createKeyAccessWithP256MLKEM768Key() throws Exception {
        roundTripThroughSPI(KeyType.HybridSecp256r1MLKEM768Key, "p256mlkem768-kid");
    }

    @Test
    void createKeyAccessWithP384MLKEM1024Key() throws Exception {
        roundTripThroughSPI(KeyType.HybridSecp384r1MLKEM1024Key, "p384mlkem1024-kid");
    }

    private void roundTripThroughSPI(KeyType keyType, String kid) throws Exception {
        HybridTestKeys.PemPair kp = HybridTestKeys.generate(keyType);

        Manifest.KeyAccess ka = createTDFAndGetFirstKeyAccess(keyType, kp.publicKeyPem, kid);
        assertThat(ka.keyType).isEqualTo("hybrid-wrapped");
        assertThat(ka.ephemeralPublicKey).isNull();
        assertThat(ka.wrappedKey).isNotEmpty();

        byte[] wrappedDer = Base64.getDecoder().decode(ka.wrappedKey);
        HybridKeyWrapProvider provider = HybridKeyWrapResolver.get(keyType);
        byte[] symKey = provider.unwrapDEK(keyType, kp.privateKeyPem, wrappedDer);
        assertThat(symKey).hasSize(32);
    }

    private Manifest.KeyAccess createTDFAndGetFirstKeyAccess(KeyType keyType, String publicKeyPem, String kid)
            throws Exception {
        Config.KASInfo kasInfo = new Config.KASInfo();
        kasInfo.URL = "https://kas.example.com";
        kasInfo.KID = kid;
        kasInfo.Algorithm = keyType.toString();
        kasInfo.PublicKey = publicKeyPem;

        SDK.KAS fakeKas = new SDK.KAS() {
            @Override
            public void close() {}

            @Override
            public Config.KASInfo getPublicKey(Config.KASInfo info) {
                Config.KASInfo copy = info.clone();
                copy.Algorithm = keyType.toString();
                copy.PublicKey = publicKeyPem;
                copy.KID = kid;
                return copy;
            }

            @Override
            public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {
                throw new UnsupportedOperationException("KAS unwrap is not exercised by hybrid TDF creation tests");
            }

            @Override
            public KASKeyCache getKeyCache() {
                return new KASKeyCache();
            }
        };

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(kasInfo));

        InputStream plaintext = new ByteArrayInputStream("hybrid hello".getBytes());
        ByteArrayOutputStream tdfOut = new ByteArrayOutputStream();

        TDF tdf = new TDF(new FakeServicesBuilder()
                .setKas(fakeKas)
                .setKeyAccessServerRegistryService(kasRegistryService)
                .build());

        Manifest manifest = tdf.createTDF(plaintext, tdfOut, config).getManifest();
        List<Manifest.KeyAccess> kaos = manifest.encryptionInformation.keyAccessObj;
        assertThat(kaos).hasSize(1);
        return kaos.get(0);
    }
}
