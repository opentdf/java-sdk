package io.opentdf.platform.sdk;

import com.connectrpc.impl.ProtocolClient;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

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