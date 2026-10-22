package io.opentdf.platform.sdk;

import okhttp3.OkHttpClient;
import okhttp3.Request;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.util.regex.Pattern;

/**
 * A read-only {@link SeekableByteChannel} over a remote resource, where every read is one
 * HTTP range request. The size is learned by probing {@code bytes=0-0}, and every later
 * response must report the same total size, so a resource that changes underneath the
 * reader is rejected rather than spliced together.
 * <p>
 * Redirects are not followed: the client handed in must have redirects disabled, and a 3xx
 * is reported as an error so the caller can use the final URL.
 */
// ponytail: no read cache, so ZipReader's small header reads cost a few dozen requests per
// load; add a read-ahead window if that shows up over a real network
class HttpRangeChannel implements SeekableByteChannel {
    private static final Pattern CONTENT_RANGE = Pattern.compile("bytes (\\d+)-(\\d+)/(\\d+)");

    private final OkHttpClient client;
    private final URI url;
    private final long size;
    private long position;
    private boolean open = true;

    HttpRangeChannel(OkHttpClient client, URI url) throws IOException {
        this.client = client;
        this.url = url;
        this.size = fetch(ByteBuffer.allocate(1), 0);
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
                throw new SDK.RangeNotSupportedException(
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
                throw new SDK.RangeNotSupportedException("invalid Content-Range " + contentRange);
            }
            long gotStart = Long.parseLong(m.group(1));
            long gotEnd = Long.parseLong(m.group(2));
            if (gotStart != offset || gotEnd != end) {
                throw new SDK.RangeNotSupportedException("requested bytes " + offset + "-" + end
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
    }

    private void ensureOpen() throws ClosedChannelException {
        if (!open) {
            throw new ClosedChannelException();
        }
    }
}
