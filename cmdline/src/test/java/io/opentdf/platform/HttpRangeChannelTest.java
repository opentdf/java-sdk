package io.opentdf.platform;

import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import io.opentdf.platform.sdk.ZipReader;
import okio.Buffer;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpRangeChannelTest {
    static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .followRedirects(false).followSslRedirects(false).build();

    private static final Pattern RANGE = Pattern.compile("bytes=(\\d+)-(\\d+)");

    /** Serves {@code data} the way a static file server does, adding the bytes sent to {@code served}. */
    static Dispatcher rangeDispatcher(Supplier<byte[]> data, AtomicLong served) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                byte[] bytes = data.get();
                var m = RANGE.matcher(String.valueOf(request.getHeader("Range")));
                if (!m.matches()) {
                    return new MockResponse().setResponseCode(200).setBody(new Buffer().write(bytes));
                }
                int start = Integer.parseInt(m.group(1));
                int end = Math.min(Integer.parseInt(m.group(2)), bytes.length - 1);
                served.addAndGet(end - start + 1);
                return new MockResponse().setResponseCode(206)
                        .setHeader("Content-Range", "bytes " + start + "-" + end + "/" + bytes.length)
                        .setBody(new Buffer().write(bytes, start, end - start + 1));
            }
        };
    }

    private static URI url(MockWebServer server) {
        return server.url("/x.tdf").uri();
    }

    @Test
    void readsAndSeeks() throws Exception {
        byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
        try (var server = new MockWebServer()) {
            server.setDispatcher(rangeDispatcher(() -> data, new AtomicLong()));
            try (var ch = new HttpRangeChannel(CLIENT, url(server))) {
                assertThat(ch.size()).isEqualTo(10);

                var buf = ByteBuffer.allocate(4);
                assertThat(ch.position(3).read(buf)).isEqualTo(4);
                assertThat(new String(buf.array(), StandardCharsets.UTF_8)).isEqualTo("3456");
                assertThat(ch.position()).isEqualTo(7);

                // clamped at the end of the resource, then EOF
                buf.clear();
                assertThat(ch.read(buf)).isEqualTo(3);
                assertThat(ch.read(buf.clear())).isEqualTo(-1);
            }
            assertThat(server.takeRequest().getHeader("Authorization")).isNull();
        }
    }

    /** Only the bytes asked for cross the wire, which is the point of reading a TDF in place. */
    @Test
    void readsOnlyTheRequestedBytes() throws Exception {
        byte[] data = new byte[100_000];
        var served = new AtomicLong();
        try (var server = new MockWebServer()) {
            server.setDispatcher(rangeDispatcher(() -> data, served));
            try (var ch = new HttpRangeChannel(CLIENT, url(server))) {
                served.set(0); // discount the one-byte size probe
                assertThat(ch.position(50_000).read(ByteBuffer.allocate(1_000))).isEqualTo(1_000);
            }
            assertThat(served).hasValue(1_000);
        }
    }

    @Test
    void usesAfterCloseAreRejected() throws Exception {
        byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
        try (var server = new MockWebServer()) {
            server.setDispatcher(rangeDispatcher(() -> data, new AtomicLong()));
            var ch = new HttpRangeChannel(CLIENT, url(server));
            ch.close();

            assertThat(ch.isOpen()).isFalse();
            assertThatThrownBy(() -> ch.read(ByteBuffer.allocate(1)))
                    .isInstanceOf(ClosedChannelException.class);
        }
    }

    @Test
    void rangeNotSupported() throws Exception {
        try (var server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setBody("not a partial response"));
            assertThatThrownBy(() -> new HttpRangeChannel(CLIENT, url(server)))
                    .isInstanceOf(HttpRangeChannel.RangeNotSupportedException.class);
        }
    }

    @Test
    void mismatchedContentRangeIsRangeNotSupported() throws Exception {
        try (var server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(206)
                    .setHeader("Content-Range", "bytes 0-9/10").setBody("0123456789"));
            assertThatThrownBy(() -> new HttpRangeChannel(CLIENT, url(server)))
                    .isInstanceOf(HttpRangeChannel.RangeNotSupportedException.class);
        }
    }

    @Test
    void errorStatusesReportTheirStatus() throws Exception {
        for (int status : new int[] { 302, 403, 404 }) {
            try (var server = new MockWebServer()) {
                server.enqueue(new MockResponse().setResponseCode(status).setHeader("Location", "/elsewhere"));
                assertThatThrownBy(() -> new HttpRangeChannel(CLIENT, url(server)))
                        .isInstanceOf(IOException.class)
                        .isNotInstanceOf(HttpRangeChannel.RangeNotSupportedException.class)
                        .hasMessageContaining(String.valueOf(status))
                        .satisfies(e -> {
                            if (status == 302) {
                                assertThat(e).hasMessageContaining("redirects are not followed");
                            }
                        });
            }
        }
    }

    @Test
    void sizeChanged() throws Exception {
        var data = new byte[][] { "0123456789".getBytes(StandardCharsets.UTF_8) };
        try (var server = new MockWebServer()) {
            server.setDispatcher(rangeDispatcher(() -> data[0], new AtomicLong()));
            try (var ch = new HttpRangeChannel(CLIENT, url(server))) {
                data[0] = "0123456789abc".getBytes(StandardCharsets.UTF_8);
                assertThatThrownBy(() -> ch.read(ByteBuffer.allocate(4)))
                        .hasMessageContaining("size changed from 10 to 13");
            }
        }
    }

    /**
     * The SDK reads a TDF as a zip over whatever channel it is handed, so the channel has to
     * satisfy ZipReader's seek-heavy access pattern -- not just the reads a test drives by hand.
     */
    @Test
    void readsAZipArchiveThroughZipReader() throws Exception {
        var zip = new ByteArrayOutputStream();
        byte[] payload = new byte[64_000];
        new java.util.Random(1).nextBytes(payload);
        // STORED, like TDFWriter writes: ZipReader hands back entry bytes as they sit in the
        // archive and does not inflate.
        try (var out = new ZipOutputStream(zip)) {
            out.setMethod(ZipOutputStream.STORED);
            out.putNextEntry(stored("0.manifest.json", "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8)));
            out.write("{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8));
            out.putNextEntry(stored("0.payload", payload));
            out.write(payload);
        }
        byte[] archive = zip.toByteArray();

        try (var server = new MockWebServer()) {
            server.setDispatcher(rangeDispatcher(() -> archive, new AtomicLong()));
            try (var ch = new HttpRangeChannel(CLIENT, url(server))) {
                var entries = new ZipReader(ch).getEntries();

                assertThat(entries).extracting(ZipReader.Entry::getName)
                        .containsExactlyInAnyOrder("0.manifest.json", "0.payload");
                var found = entries.stream().filter(e -> e.getName().equals("0.payload")).findFirst().orElseThrow();
                try (var data = found.getData()) {
                    assertThat(data.readAllBytes()).isEqualTo(payload);
                }
            }
        }
    }

    private static ZipEntry stored(String name, byte[] data) {
        var crc = new CRC32();
        crc.update(data);
        var entry = new ZipEntry(name);
        entry.setMethod(ZipEntry.STORED);
        entry.setSize(data.length);
        entry.setCompressedSize(data.length);
        entry.setCrc(crc.getValue());
        return entry;
    }

    /** The scheme is checked before the SDK is touched, so a null SDK is enough here. */
    @Test
    void rejectsNonHttpSchemes() {
        assertThatThrownBy(() -> HttpRangeChannel.open(null, URI.create("file:///etc/passwd")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("file");
    }
}
