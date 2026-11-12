package io.opentdf.platform;

import io.opentdf.platform.sdk.SDK;
import okhttp3.OkHttpClient;
import okhttp3.Request;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;

/**
 * A read-only {@link SeekableByteChannel} over a remote resource, where every read is one
 * HTTP range request. Handed to {@link SDK#loadTDF(SeekableByteChannel, io.opentdf.platform.sdk.Config.TDFReaderConfig)}
 * it lets the SDK read a TDF in place, downloading only the bytes it actually touches.
 * <p>
 * The size is learned by probing {@code bytes=0-0}, and every later response must report the
 * same total size, so a resource that changes underneath the reader is rejected rather than
 * spliced together.
 * <p>
 * Redirects are not followed, and a 3xx is reported as an error so the caller can use the
 * final URL.
 */
// TODO: Add a read-ahead window if small ZIP header reads become a network bottleneck.
class HttpRangeChannel implements SeekableByteChannel {
    private static final Pattern CONTENT_RANGE = Pattern.compile("bytes (\\d+)-(\\d+)/(\\d+)");

    private final OkHttpClient client;
    // Set only when this channel built the client, and so must shut it down on close.
    private final boolean ownsClient;
    private final URI url;
    private final long size;
    private long position;
    private boolean open = true;

    /**
     * Opens {@code url} with a client that is unauthenticated -- platform credentials never go
     * to the TDF host -- but that keeps the TLS settings the SDK was built with, so {@code
     * --insecure} applies here too.
     */
    static HttpRangeChannel open(SDK sdk, URI url) throws IOException {
        String scheme = url.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("unsupported URL scheme: " + scheme);
        }
        return new HttpRangeChannel(rangeClient(sdk), true, url);
    }

    HttpRangeChannel(OkHttpClient client, URI url) throws IOException {
        this(client, false, url);
    }

    private HttpRangeChannel(OkHttpClient client, boolean ownsClient, URI url) throws IOException {
        this.client = client;
        this.ownsClient = ownsClient;
        this.url = url;
        try {
            this.size = fetch(ByteBuffer.allocate(1), 0);
        } catch (IOException | RuntimeException e) {
            shutdown();
            throw e;
        }
    }

    private static OkHttpClient rangeClient(SDK sdk) {
        // A plain client rather than one derived from the SDK's: the SDK's carries the auth
        // interceptor, and under --plaintext it is pinned to h2c prior knowledge, while a TDF
        // host is an ordinary HTTP server. Default protocols (HTTP/2, HTTP/1.1) are right here.
        var builder = new OkHttpClient.Builder().followRedirects(false).followSslRedirects(false);
        var trustManager = sdk.getTrustManager().orElse(null);
        if (trustManager instanceof X509TrustManager) {
            var x509 = (X509TrustManager) trustManager;
            try {
                var context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[] { x509 }, null);
                builder.sslSocketFactory(context.getSocketFactory(), x509);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("could not build a TLS context for range requests", e);
            }
        }
        return builder.build();
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        ensureOpen();
        if (position >= size) {
            return -1;
        }
        int len = (int) Math.min(dst.remaining(), size - position);
        if (len == 0) {
            return 0;
        }
        var window = dst.slice();
        window.limit(len);
        long total = fetch(window, position);
        if (total != size) {
            throw new IOException("remote resource size changed from " + size + " to " + total + " bytes");
        }
        dst.position(dst.position() + len);
        position += len;
        return len;
    }

    /**
     * Fills {@code dst} with the bytes starting at {@code offset} and returns the total size
     * of the resource as reported by the server.
     */
    private long fetch(ByteBuffer dst, long offset) throws IOException {
        long end = offset + dst.remaining() - 1;
        var request = new Request.Builder()
                .url(url.toString())
                .header("Range", "bytes=" + offset + "-" + end)
                .build();
        try (var response = client.newCall(request).execute()) {
            int status = response.code();
            if (status == 200) {
                throw new RangeNotSupportedException(
                        "status 200 for bytes " + offset + "-" + end);
            }
            if (status >= 300 && status < 400) {
                throw new IOException("range request redirected (" + status
                        + "); redirects are not followed, use the final URL");
            }
            if (status != 206) {
                throw new IOException("range request for bytes " + offset + "-" + end + " failed: " + status);
            }
            String contentRange = response.header("Content-Range");
            var m = contentRange == null ? null : CONTENT_RANGE.matcher(contentRange);
            if (m == null || !m.matches()) {
                throw new RangeNotSupportedException("invalid Content-Range " + contentRange);
            }
            long gotStart = Long.parseLong(m.group(1));
            long gotEnd = Long.parseLong(m.group(2));
            if (gotStart != offset || gotEnd != end) {
                throw new RangeNotSupportedException("requested bytes " + offset + "-" + end
                        + ", got " + gotStart + "-" + gotEnd);
            }
            var source = response.body().source();
            while (dst.hasRemaining()) {
                if (source.read(dst) < 0) {
                    throw new IOException("range response for bytes " + offset + "-" + end + " ended early");
                }
            }
            return Long.parseLong(m.group(3));
        }
    }

    @Override
    public long position() throws IOException {
        ensureOpen();
        return position;
    }

    @Override
    public SeekableByteChannel position(long newPosition) throws IOException {
        ensureOpen();
        if (newPosition < 0) {
            throw new IllegalArgumentException("negative position " + newPosition);
        }
        position = newPosition;
        return this;
    }

    @Override
    public long size() throws IOException {
        ensureOpen();
        return size;
    }

    @Override
    public int write(ByteBuffer src) {
        throw new NonWritableChannelException();
    }

    @Override
    public SeekableByteChannel truncate(long size) {
        throw new NonWritableChannelException();
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public void close() {
        open = false;
        shutdown();
    }

    private void shutdown() {
        if (ownsClient) {
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
    }

    private void ensureOpen() throws ClosedChannelException {
        if (!open) {
            throw new ClosedChannelException();
        }
    }

    /**
     * The server holding a TDF did not honor an HTTP range request, so the TDF cannot be
     * read in place; download it and decrypt it from a file instead.
     */
    static class RangeNotSupportedException extends IOException {
        RangeNotSupportedException(String errorMessage) {
            super("server did not honor the HTTP range request: " + errorMessage);
        }
    }
}
