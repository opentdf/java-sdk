package io.opentdf.platform.sdk;

import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.Buffer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.regex.Pattern;

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

    @Test
    void rangeNotSupported() throws Exception {
        try (var server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setBody("not a partial response"));
            assertThatThrownBy(() -> new HttpRangeChannel(CLIENT, url(server)))
                    .isInstanceOf(SDK.RangeNotSupportedException.class);
        }
    }

    @Test
    void mismatchedContentRangeIsRangeNotSupported() throws Exception {
        try (var server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(206)
                    .setHeader("Content-Range", "bytes 0-9/10").setBody("0123456789"));
            assertThatThrownBy(() -> new HttpRangeChannel(CLIENT, url(server)))
                    .isInstanceOf(SDK.RangeNotSupportedException.class);
        }
    }

    @Test
    void errorStatusesReportTheirStatus() throws Exception {
        for (int status : new int[] { 302, 403, 404 }) {
            try (var server = new MockWebServer()) {
                server.enqueue(new MockResponse().setResponseCode(status).setHeader("Location", "/elsewhere"));
                assertThatThrownBy(() -> new HttpRangeChannel(CLIENT, url(server)))
                        .isInstanceOf(IOException.class)
                        .isNotInstanceOf(SDK.RangeNotSupportedException.class)
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

    @Test
    void rejectsNonHttpSchemes() {
        var sdk = new SDK(new FakeServicesBuilder().build(), null, null, null, null, null);
        assertThatThrownBy(() -> sdk.loadTDF(URI.create("file:///etc/passwd"), Config.newTDFReaderConfig()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
