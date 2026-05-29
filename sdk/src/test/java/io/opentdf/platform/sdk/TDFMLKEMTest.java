package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;
import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Producer-side integration test for pure ML-KEM key access. Drives
 * {@link TDF#createTDF} with each ML-KEM {@link KeyType}; asserts the resulting
 * manifest matches the wire format that the Go KAS expects (mirrors
 * {@code lib/ocrypto/mlkem_key_pair.go} in opentdf/platform PR 3491):
 * <ul>
 *   <li>{@code keyAccess.type == "wrapped"} (reused from the RSA slot)</li>
 *   <li>{@code ephemeralPublicKey} is null/empty</li>
 *   <li>{@code wrappedKey} decoded length == {@code ciphertextSize + 12 + 32 + 16}</li>
 * </ul>
 * Round-trips the wrappedKey through the matching private key locally to
 * confirm the producer/consumer wire format agrees.
 */
class TDFMLKEMTest {

    private static KeyAccessServerRegistryServiceClient kasRegistryService;
    private static final String KAS_URL = "https://kas.example.com";

    @BeforeAll
    static void setupRegistryMock() {
        kasRegistryService = mock(KeyAccessServerRegistryServiceClient.class);
        ListKeyAccessServersResponse response = ListKeyAccessServersResponse.newBuilder()
                .addKeyAccessServers(KeyAccessServer.newBuilder().setUri(KAS_URL).build())
                .build();
        when(kasRegistryService.listKeyAccessServersBlocking(any(ListKeyAccessServersRequest.class), any()))
                .thenReturn(new UnaryBlockingCall<>() {
                    @Override
                    public ResponseMessage<ListKeyAccessServersResponse> execute() {
                        return new ResponseMessage.Success<>(response,
                                Collections.emptyMap(), Collections.emptyMap());
                    }
                    @Override public void cancel() {}
                });
    }

    @ParameterizedTest
    @EnumSource(value = KeyType.class, names = {"MLKEM768Key", "MLKEM1024Key"})
    void createTDFProducesMLKEMWrappedKeyAccess(KeyType keyType) throws Exception {
        MLKEMKeyPair alg = MLKEMKeyPair.forKeyType(keyType);
        MLKEMKeyPair kp = alg.generate();
        String pubPem = kp.publicKeyInPemFormat();
        byte[] privSeed = alg.privateKeyFromPem(kp.privateKeyInPemFormat());

        // Stub the SDK.KAS so getPublicKey returns the generated ML-KEM PEM.
        // No unwrap mock is needed because this test never calls loadTDF.
        SDK.KAS kasStub = new SDK.KAS() {
            @Override public void close() {}
            @Override public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
                Config.KASInfo out = new Config.KASInfo();
                out.URL = kasInfo.URL;
                out.KID = "mlkem-test-kid";
                out.Algorithm = keyType.toString();
                out.PublicKey = pubPem;
                return out;
            }
            @Override public byte[] unwrap(Manifest.KeyAccess ka, String policy, KeyType skt) {
                throw new UnsupportedOperationException("not used in this test");
            }
            @Override public KASKeyCache getKeyCache() { return new KASKeyCache(); }
        };

        Config.KASInfo kasInfo = new Config.KASInfo();
        kasInfo.URL = KAS_URL;

        Config.TDFConfig cfg = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(kasInfo),
                Config.WithWrappingKeyAlg(keyType));

        TDF tdf = new TDF(new FakeServicesBuilder()
                .setKas(kasStub)
                .setKeyAccessServerRegistryService(kasRegistryService)
                .build());

        ByteArrayOutputStream tdfOut = new ByteArrayOutputStream();
        var manifest = tdf.createTDF(
                new ByteArrayInputStream("ml-kem round-trip payload".getBytes()),
                tdfOut, cfg).getManifest();

        assertThat(manifest.encryptionInformation.keyAccessObj).hasSize(1);
        Manifest.KeyAccess ka = manifest.encryptionInformation.keyAccessObj.get(0);

        // Wire-format invariants the KAS depends on.
        assertThat(ka.keyType).isEqualTo("wrapped");           // serialized as JSON "type"
        assertThat(ka.ephemeralPublicKey).isNullOrEmpty();
        assertThat(ka.wrappedKey).isNotEmpty();

        // wrappedKey layout: mlkem_ct || AES-GCM(nonce(12) || DEK(32) || tag(16))
        byte[] wrappedBytes = Base64.getDecoder().decode(ka.wrappedKey);
        assertThat(wrappedBytes.length).isEqualTo(alg.ciphertextSize() + 12 + 32 + 16);

        // Round-trip the wrappedKey through the matching private key.
        byte[] symKey = alg.unwrapDEK(privSeed, wrappedBytes);
        assertThat(symKey).hasSize(32);
    }
}
