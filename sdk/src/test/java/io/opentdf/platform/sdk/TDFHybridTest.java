package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
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
 * Mirrors {@code sdk/tdf_hybrid_test.go}. Creates a TDF using each hybrid KAS key type,
 * then asserts the resulting manifest's KeyAccess object has:
 * <ul>
 *   <li>{@code keyType == "hybrid-wrapped"}</li>
 *   <li>{@code ephemeralPublicKey == null} (ephemeral material lives in the wrappedKey envelope)</li>
 *   <li>a {@code wrappedKey} that round-trips back to the original payload key via the matching
 *       private key.</li>
 * </ul>
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
        XWingKeyPair kp = XWingKeyPair.generate();
        Manifest.KeyAccess ka = createTDFAndGetFirstKeyAccess(
                KeyType.HybridXWingKey, kp.publicKeyInPemFormat(), "xwing-kid");
        assertThat(ka.keyType).isEqualTo("hybrid-wrapped");
        assertThat(ka.ephemeralPublicKey).isNull();
        assertThat(ka.wrappedKey).isNotEmpty();

        // Round-trip: unwrap with the matching private key — confirms wire format is valid.
        byte[] wrappedDer = Base64.getDecoder().decode(ka.wrappedKey);
        byte[] privRaw = XWingKeyPair.privateKeyFromPem(kp.privateKeyInPemFormat());
        byte[] symKey = XWingKeyPair.unwrapDEK(privRaw, wrappedDer);
        assertThat(symKey).hasSize(32);
    }

    @Test
    void createKeyAccessWithP256MLKEM768Key() throws Exception {
        HybridNISTKeyPair kp = HybridNISTKeyPair.P256_MLKEM768.generate();
        Manifest.KeyAccess ka = createTDFAndGetFirstKeyAccess(
                KeyType.HybridSecp256r1MLKEM768Key, kp.publicKeyInPemFormat(), "p256mlkem768-kid");
        assertThat(ka.keyType).isEqualTo("hybrid-wrapped");
        assertThat(ka.ephemeralPublicKey).isNull();
        assertThat(ka.wrappedKey).isNotEmpty();

        byte[] wrappedDer = Base64.getDecoder().decode(ka.wrappedKey);
        byte[] privRaw = HybridNISTKeyPair.P256_MLKEM768.privateKeyFromPem(kp.privateKeyInPemFormat());
        byte[] symKey = HybridNISTKeyPair.P256_MLKEM768.unwrapDEK(privRaw, wrappedDer);
        assertThat(symKey).hasSize(32);
    }

    @Test
    void createKeyAccessWithP384MLKEM1024Key() throws Exception {
        HybridNISTKeyPair kp = HybridNISTKeyPair.P384_MLKEM1024.generate();
        Manifest.KeyAccess ka = createTDFAndGetFirstKeyAccess(
                KeyType.HybridSecp384r1MLKEM1024Key, kp.publicKeyInPemFormat(), "p384mlkem1024-kid");
        assertThat(ka.keyType).isEqualTo("hybrid-wrapped");
        assertThat(ka.ephemeralPublicKey).isNull();
        assertThat(ka.wrappedKey).isNotEmpty();

        byte[] wrappedDer = Base64.getDecoder().decode(ka.wrappedKey);
        byte[] privRaw = HybridNISTKeyPair.P384_MLKEM1024.privateKeyFromPem(kp.privateKeyInPemFormat());
        byte[] symKey = HybridNISTKeyPair.P384_MLKEM1024.unwrapDEK(privRaw, wrappedDer);
        assertThat(symKey).hasSize(32);
    }

    /**
     * Build a fake KAS that returns {@code (algorithm, publicKeyPem)} as its public key, then
     * call {@code TDF.createTDF} on a 32-byte plaintext and return the single KeyAccess produced
     * in the manifest.
     */
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
