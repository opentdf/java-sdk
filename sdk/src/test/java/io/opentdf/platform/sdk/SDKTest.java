package io.opentdf.platform.sdk;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

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
    void testReadingRandomBytes() {
        var tdf = new byte[2023];
        new Random().nextBytes(tdf);

        assertThat(SDK.isTDF(new SeekableInMemoryByteChannel(tdf))).isFalse();
    }
}