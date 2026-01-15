package io.opentdf.platform.sdk;

import com.connectrpc.impl.ProtocolClient;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SDKTest {

    @Test
    void testExaminingValidZTDF() throws IOException {
        try (var ztdf = SDKTest.class.getClassLoader().getResourceAsStream("sample.txt.tdf")) {
            assert ztdf != null;
            var chan = new SeekableInMemoryByteChannel(ztdf.readAllBytes());
            assertThat(SDK.isTDF(chan)).isTrue();
        }
    }

    @Test
    void testReadingProtocolClient() {
        var platformServicesClient = mock(ProtocolClient.class);
        var sdk = new SDK(new FakeServicesBuilder().build(), null, null, platformServicesClient, null);
        assertThat(sdk.getPlatformServicesClient()).isSameAs(platformServicesClient);
    }

    @Test
    void testGettingBaseKey() {
        var platformServicesClient = mock(ProtocolClient.class);
        var wellknownService = Mockito.mock(WellKnownServiceClientInterface.class);
        var baseKeyJson = "{\"kas_url\":\"https://example.com/base_key\",\"public_key\":{\"algorithm\":\"ALGORITHM_RSA_2048\",\"kid\":\"thekid\",\"pem\": \"thepem\"}}";
        var val = Value.newBuilder().setStringValue(baseKeyJson).build();
        var config = Struct.newBuilder().putFields("base_key", val).build();
        var response = GetWellKnownConfigurationResponse
                .newBuilder()
                .setConfiguration(config)
                .build();

        Mockito.when(wellknownService.getWellKnownConfigurationBlocking(Mockito.any(), Mockito.anyMap()))
                .thenReturn(TestUtil.successfulUnaryCall(response));

        var services = new FakeServicesBuilder().setWellknownService(wellknownService).build();
        var sdk = new SDK(services, null, null, platformServicesClient, null);

        var baseKey = sdk.getBaseKey();
        assertThat(baseKey).isPresent();
        var simpleKasKey = baseKey.get();
        assertThat(simpleKasKey.getKasUri()).isEqualTo("https://example.com/base_key");
        assertThat(simpleKasKey.getPublicKey().getAlgorithm()).isEqualTo(Algorithm.ALGORITHM_RSA_2048);
        assertThat(simpleKasKey.getPublicKey().getKid()).isEqualTo("thekid");
        assertThat(simpleKasKey.getPublicKey().getPem()).isEqualTo("thepem");
    }

    @Test
    void testAuthorizationServiceClientV2() {
        var platformServicesClient = mock(ProtocolClient.class);
        io.opentdf.platform.authorization.v2.AuthorizationServiceClientInterface authSvcV2 = mock(io.opentdf.platform.authorization.v2.AuthorizationServiceClientInterface.class);
        var fakeServiceBuilder = new FakeServicesBuilder().setAuthorizationServiceV2(authSvcV2).build();
        var sdk = new SDK(fakeServiceBuilder, null, null, platformServicesClient, null);
        assertThat(sdk.getServices().authorizationV2()).isSameAs(fakeServiceBuilder.authorizationV2());
    }

    @Test
    void testExaminingInvalidFile() {
        var chan = new SeekableByteChannel() {
            @Override
            public boolean isOpen() {
                return false;
            }

            @Override
            public void close() {

            }

            @Override
            public int read(ByteBuffer dst) {
                return 0;
            }

            @Override
            public int write(ByteBuffer src) {
                return 0;
            }

            @Override
            public long position() {
                return 0;
            }

            @Override
            public SeekableByteChannel position(long newPosition) {
                return this;
            }

            @Override
            public long size() {
                return 0;
            }

            @Override
            public SeekableByteChannel truncate(long size) {
                return null;
            }
        };

        assertThat(SDK.isTDF(chan)).isFalse();
    }

    @Test
    void testExaminingManifest() throws IOException {
        try (var tdfStream = SDKTest.class.getClassLoader().getResourceAsStream("sample.txt.tdf")) {
            assertThat(tdfStream)
                    .withFailMessage("sample.txt.tdf not found in classpath")
                    .isNotNull();
            var manifest = SDK.readManifest(new SeekableInMemoryByteChannel(tdfStream.readAllBytes()));
            assertThat(manifest).isNotNull();
            assertThat(manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault)
                    .isEqualTo(1048604);
            var policyObject = SDK.decodePolicyObject(manifest);
            assertThat(policyObject.uuid).isEqualTo("98bb8a81-5217-4a31-8852-932d29d71aac");
        }
    }

    @Test
    void testReadingRandomBytes() {
        var tdf = new byte[2023];
        new Random().nextBytes(tdf);

        assertThat(SDK.isTDF(new SeekableInMemoryByteChannel(tdf))).isFalse();
    }
}
