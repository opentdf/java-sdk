package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.pqc.bc.MLKEMAlgorithm;
import io.opentdf.platform.sdk.pqc.bc.MLKEMKeyPair;
import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Mirrors {@code TDFHybridTest} for pure ML-KEM (FIPS 203). Creates a TDF
 * using each ML-KEM KAS key type, then asserts the manifest's KeyAccess
 * object has:
 * <ul>
 *   <li>{@code keyType == "mlkem-wrapped"} — its own KAO scheme, distinct
 *       from RSA's {@code "wrapped"} and the hybrid {@code "hybrid-wrapped"}.
 *       The KAS uses this to skip HKDF on the wrap key. See platform PR
 *       #3562 and {@code adr/decisions/2026-06-16-mlkem-direct-key-wrap.md}.</li>
 *   <li>{@code ephemeralPublicKey == null}</li>
 *   <li>a {@code wrappedKey} (ASN.1 envelope, base64'd) that round-trips
 *       back to the 32-byte payload key via the matching private key.</li>
 * </ul>
 */
class TDFMLKEMTest {

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
                    public void cancel() {
                        // No-op: the mock call is synchronous and already complete by the time
                        // the SDK could call cancel(); nothing to interrupt.
                    }
                });
    }

    @Test
    void createKeyAccessWithMLKEM768() throws Exception {
        assertRoundTripFor(MLKEMAlgorithm.MLKEM_768, KeyType.MLKEM768Key, "mlkem768-kid");
    }

    @Test
    void createKeyAccessWithMLKEM1024() throws Exception {
        assertRoundTripFor(MLKEMAlgorithm.MLKEM_1024, KeyType.MLKEM1024Key, "mlkem1024-kid");
    }

    private void assertRoundTripFor(MLKEMAlgorithm algo, KeyType keyType, String kid) throws Exception {
        MLKEMKeyPair kp = algo.generate();
        Manifest.KeyAccess ka = createTDFAndGetFirstKeyAccess(
                keyType, kp.publicKeyInPemFormat(), kid);

        assertThat(ka.keyType).isEqualTo("mlkem-wrapped");
        assertThat(ka.ephemeralPublicKey).isNull();
        assertThat(ka.wrappedKey).isNotEmpty();

        byte[] wrapped = Base64.getDecoder().decode(ka.wrappedKey);
        // ASN.1 SEQUENCE tag (same envelope as hybrid). Round-trip is the wire-format guard.
        assertThat(wrapped[0]).isEqualTo((byte) 0x30);

        byte[] privRaw = algo.privateKeyFromPem(kp.privateKeyInPemFormat());
        byte[] symKey = algo.unwrapDEK(privRaw, wrapped);
        assertThat(symKey).hasSize(32);
    }

    /**
     * Build a fake KAS that returns {@code (algorithm, publicKeyPem)} as its public key, then
     * call {@code TDF.createTDF} on a small plaintext and return the single KeyAccess produced
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
                throw new UnsupportedOperationException("KAS unwrap is not exercised by pure-MLKEM TDF creation tests");
            }

            @Override
            public KASKeyCache getKeyCache() {
                return new KASKeyCache();
            }
        };

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withAutoconfigure(false),
                Config.withKasInformation(kasInfo));

        InputStream plaintext = new ByteArrayInputStream("mlkem hello".getBytes(StandardCharsets.UTF_8));
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
