package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the compact {@link Manifest.Segments} representation: it has to
 * serialize exactly like a plain list, fall back when a manifest does not fit
 * its assumptions, and let a manifest larger than a Java String round trip.
 */
public class SegmentsTest {

    private static final Gson GSON = new Gson();
    private static final int SEGMENT_SIZE = 16384;
    private static final int ENCRYPTED_SEGMENT_SIZE = SEGMENT_SIZE + 28;

    private static String hash(int i) {
        var bytes = new byte[16];
        bytes[0] = (byte) i;
        bytes[1] = (byte) (i >> 8);
        bytes[2] = (byte) (i >> 16);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Manifest.Segment segment(String hash, long segmentSize, long encryptedSegmentSize) {
        var segment = new Manifest.Segment();
        segment.hash = hash;
        segment.segmentSize = segmentSize;
        segment.encryptedSegmentSize = encryptedSegmentSize;
        return segment;
    }

    private static String manifestJson(List<Manifest.Segment> segments) {
        return "{\"schemaVersion\":\"4.3.0\",\"encryptionInformation\":{\"type\":\"split\","
                // no '=' padding: Gson HTML-escapes it, and this literal is compared verbatim
                + "\"policy\":\"eyJib2R5Ijp7fX0K\",\"keyAccess\":[{\"type\":\"wrapped\",\"url\":\"http://kas\","
                + "\"protocol\":\"kas\",\"wrappedKey\":\"AAAA\"}],"
                + "\"method\":{\"algorithm\":\"AES-256-GCM\",\"iv\":\"AAAAAAAAAAAA\",\"isStreamable\":true},"
                + "\"integrityInformation\":{\"rootSignature\":{\"alg\":\"GMAC\",\"sig\":\"AAAA\"},"
                + "\"segmentHashAlg\":\"GMAC\",\"segmentSizeDefault\":" + SEGMENT_SIZE
                + ",\"encryptedSegmentSizeDefault\":" + ENCRYPTED_SEGMENT_SIZE + ",\"segments\":"
                + segments.stream().map(GSON::toJson).collect(Collectors.joining(",", "[", "]"))
                + "}},\"payload\":{\"type\":\"reference\",\"url\":\"0.payload\",\"protocol\":\"zip\","
                + "\"mimeType\":\"application/octet-stream\",\"isEncrypted\":true},\"assertions\":[]}";
    }

    /** A run of uniform segments with a short final one, i.e. what this SDK writes. */
    private static List<Manifest.Segment> uniformSegments(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> segment(hash(i),
                        i == count - 1 ? 7 : SEGMENT_SIZE,
                        i == count - 1 ? 35 : ENCRYPTED_SEGMENT_SIZE))
                .collect(Collectors.toList());
    }

    @Test
    void uniformSegmentsAreStoredCompactlyAndSerializeUnchanged() {
        var segments = uniformSegments(5);
        var json = manifestJson(segments);

        var manifest = Manifest.readManifest(json);
        var parsed = manifest.encryptionInformation.integrityInformation.segments;

        assertThat(parsed).isInstanceOf(Manifest.Segments.class);
        assertThat(parsed).containsExactlyElementsOf(segments);
        assertThat(Manifest.toJson(manifest)).isEqualTo(json);
    }

    @Test
    void irregularSegmentSizesFallBackToAPlainList() {
        var segments = new ArrayList<>(uniformSegments(3));
        // a non-final segment that disagrees with the defaults cannot be stored compactly
        segments.set(1, segment(hash(1), SEGMENT_SIZE / 2, ENCRYPTED_SEGMENT_SIZE / 2));
        var json = manifestJson(segments);

        var manifest = Manifest.readManifest(json);
        var parsed = manifest.encryptionInformation.integrityInformation.segments;

        assertThat(parsed).isNotInstanceOf(Manifest.Segments.class);
        assertThat(parsed).containsExactlyElementsOf(segments);
        assertThat(Manifest.toJson(manifest)).isEqualTo(json);
    }

    @Test
    void segmentsWithDifferingHashLengthsFallBackToAPlainList() {
        var segments = new ArrayList<>(uniformSegments(3));
        segments.set(1, segment("deadbeef", SEGMENT_SIZE, ENCRYPTED_SEGMENT_SIZE));
        var json = manifestJson(segments);

        var parsed = Manifest.readManifest(json).encryptionInformation.integrityInformation.segments;

        assertThat(parsed).isNotInstanceOf(Manifest.Segments.class);
        assertThat(parsed).containsExactlyElementsOf(segments);
    }

    @Test
    void anAbsurdlyLongHashFallsBackInsteadOfSizingAChunkFromIt() {
        // a chunk is stride * 4096 bytes, so without a bound this one hash would ask for
        // gigabytes before the fallback ever ran
        var segments = new ArrayList<>(uniformSegments(2));
        segments.set(0, segment("A".repeat(100_000), SEGMENT_SIZE, ENCRYPTED_SEGMENT_SIZE));

        var parsed = Manifest.readManifest(manifestJson(segments))
                .encryptionInformation.integrityInformation.segments;

        assertThat(parsed).isNotInstanceOf(Manifest.Segments.class);
        assertThat(parsed).containsExactlyElementsOf(segments);
    }

    @Test
    void aggregateConcatenatesEveryHash() {
        var segments = new Manifest.Segments();
        for (int i = 0; i < 3; i++) {
            assertThat(segments.append(hash(i), SEGMENT_SIZE, ENCRYPTED_SEGMENT_SIZE)).isTrue();
        }

        var decoded = new byte[48];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(Base64.getDecoder().decode(hash(i)), 0, decoded, i * 16, 16);
        }
        assertThat(segments.aggregate(true)).isEqualTo(decoded);
        assertThat(segments.aggregate(false))
                .isEqualTo((hash(0) + hash(1) + hash(2)).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    void emptySegmentsAggregateToNothing() {
        assertThat(new Manifest.Segments().aggregate(true)).isEmpty();
        assertThat(new Manifest.Segments().aggregate(false)).isEmpty();
    }

    /**
     * A manifest whose JSON is larger than {@code Integer.MAX_VALUE} cannot be held
     * as a String, so both directions have to stream. Opt in with
     * {@code -Dtdf.hugeSegments=true -Xmx2g}; it needs roughly a minute and 1 GiB.
     */
    @Test
    @EnabledIfSystemProperty(named = "tdf.hugeSegments", matches = "true")
    void aManifestTooLargeToBeAStringRoundTrips() throws IOException {
        // ~25M segments at ~99 JSON bytes each is ~2.5 GB, past the String ceiling
        final int count = 25_000_000;

        Manifest manifest;
        try (Reader json = new GeneratedManifestReader(count)) {
            manifest = Manifest.readManifest(json);
        }
        var segments = manifest.encryptionInformation.integrityInformation.segments;
        assertThat(segments).isInstanceOf(Manifest.Segments.class);
        assertThat(segments.size()).isEqualTo(count);
        assertThat(segments.get(count - 1).hash).isEqualTo(hash(count - 1));

        var counting = new CountingWriter();
        new Gson().toJson(manifest, counting);
        assertThat(counting.written).isGreaterThan(Integer.MAX_VALUE);
    }

    /** Renders a manifest with {@code count} segments without ever storing it. */
    private static final class GeneratedManifestReader extends Reader {
        private final int count;
        private final String suffix;
        private int next;
        private String pending;
        private int pendingOffset;

        GeneratedManifestReader(int count) {
            this.count = count;
            var template = manifestJson(uniformSegments(1));
            this.pending = template.substring(0, template.indexOf("\"segments\":[") + "\"segments\":[".length());
            this.suffix = template.substring(template.indexOf("]}},\"payload\""));
        }

        @Override
        public int read(char[] buffer, int offset, int length) {
            if (pendingOffset == pending.length()) {
                if (next > count) {
                    return -1;
                }
                pending = next == count ? suffix
                        : (next == 0 ? "" : ",") + GSON.toJson(segment(hash(next),
                                next == count - 1 ? 7 : SEGMENT_SIZE,
                                next == count - 1 ? 35 : ENCRYPTED_SEGMENT_SIZE));
                pendingOffset = 0;
                next++;
                if (pending.isEmpty()) {
                    return read(buffer, offset, length);
                }
            }
            int n = Math.min(length, pending.length() - pendingOffset);
            pending.getChars(pendingOffset, pendingOffset + n, buffer, offset);
            pendingOffset += n;
            return n;
        }

        @Override
        public void close() {
        }
    }

    private static final class CountingWriter extends Writer {
        private long written;

        @Override
        public void write(char[] buffer, int offset, int length) {
            written += length;
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }
}
