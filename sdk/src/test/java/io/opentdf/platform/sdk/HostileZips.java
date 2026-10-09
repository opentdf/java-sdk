package io.opentdf.platform.sdk;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Builds small stored (uncompressed) zip archives by hand, so that a test can put any value it
 * likes into a central directory field. {@link ZipWriter} and other writers only produce honest
 * archives; these are for the hostile shapes from DSPX-5103, where lengths, sizes and offsets
 * read as negative or point outside the archive.
 */
final class HostileZips {
    private HostileZips() {
    }

    /** One archive entry, plus overrides for what its central directory header claims. */
    static final class Entry {
        final String name;
        final byte[] data;
        byte[] centralExtra = new byte[0];
        Long compressedSize;
        Long uncompressedSize;
        Long localHeaderOffset;
        Integer fileNameLength;
        Integer extraFieldLength;
        Integer fileCommentLength;

        Entry(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    /**
     * A minimal TDF-shaped archive: a payload and a manifest. {@code hostile} adjusts the
     * manifest entry, which is written last so its central directory header is the last one.
     */
    static byte[] tdfWith(String manifestJson, Consumer<Entry> hostile) {
        var payload = new Entry("0.payload", "payload bytes".getBytes(StandardCharsets.UTF_8));
        var manifest = new Entry("0.manifest.json", manifestJson.getBytes(StandardCharsets.UTF_8));
        hostile.accept(manifest);
        return build(List.of(payload, manifest));
    }

    /** The named hostile shapes, each applied to the manifest entry of {@link #tdfWith}. */
    static Map<String, Consumer<Entry>> hostileShapes() {
        var shapes = new LinkedHashMap<String, Consumer<Entry>>();
        // the shape that looped forever when the data size was read signed: 0xFFFC is -4,
        // which sent the position straight back to the start of the record
        shapes.put("extra field data size 0xFFFC", e -> e.centralExtra = extraRecord(0xCAFE, 0xFFFC, new byte[4]));
        shapes.put("extra field data size past the extra field", e -> e.centralExtra = extraRecord(0xCAFE, 16, new byte[4]));
        shapes.put("zip64 local header offset 0xFFFFFFFFFFFFFFFF", e -> {
            e.localHeaderOffset = 0xFFFFFFFFL;
            e.centralExtra = extraRecord(0x0001, 8, longs(-1L));
        });
        shapes.put("zip64 uncompressed size 0xFFFFFFFFFFFFFFFF", e -> {
            e.uncompressedSize = 0xFFFFFFFFL;
            e.centralExtra = extraRecord(0x0001, 8, longs(-1L));
        });
        shapes.put("zip64 compressed size Long.MIN_VALUE", e -> {
            e.compressedSize = 0xFFFFFFFFL;
            e.centralExtra = extraRecord(0x0001, 8, longs(Long.MIN_VALUE));
        });
        // both sizes carry the sentinel, but the record only has room for one of them; the
        // second must not be read out of whatever follows the record
        shapes.put("zip64 extra field too short for its sentinels", e -> {
            e.uncompressedSize = 0xFFFFFFFFL;
            e.compressedSize = 0xFFFFFFFFL;
            e.centralExtra = concat(extraRecord(0x0001, 8, longs(e.data.length)), extraRecord(0xCAFE, 4, new byte[4]));
        });
        shapes.put("file name length 0xFFFF", e -> e.fileNameLength = 0xFFFF);
        shapes.put("extra field length 0xFFFF", e -> e.extraFieldLength = 0xFFFF);
        shapes.put("file comment length 0xFFFF", e -> e.fileCommentLength = 0xFFFF);
        shapes.put("local header offset 0xFFFFFFF0", e -> e.localHeaderOffset = 0xFFFFFFF0L);
        shapes.put("compressed size 0x7FFFFFFF", e -> e.compressedSize = 0x7FFFFFFFL);
        return shapes;
    }

    static byte[] extraRecord(int headerId, int dataSize, byte[] data) {
        var buf = ByteBuffer.allocate(4 + data.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort((short) headerId).putShort((short) dataSize).put(data);
        return buf.array();
    }

    static byte[] longs(long... values) {
        var buf = ByteBuffer.allocate(values.length * Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        for (long v : values) {
            buf.putLong(v);
        }
        return buf.array();
    }

    static byte[] concat(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (var p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    static byte[] build(List<Entry> entries) {
        var out = new ByteArrayOutputStream();
        var offsets = new ArrayList<Long>();
        for (var e : entries) {
            offsets.add((long) out.size());
            var name = e.name.getBytes(StandardCharsets.UTF_8);
            var local = ByteBuffer.allocate(30 + name.length).order(ByteOrder.LITTLE_ENDIAN);
            local.putInt(0x04034b50)
                    .putShort((short) 20) // version needed
                    .putShort((short) 0) // flags
                    .putShort((short) 0) // stored
                    .putShort((short) 0).putShort((short) 0) // time, date
                    .putInt(0) // crc, unchecked by the reader
                    .putInt(e.data.length).putInt(e.data.length)
                    .putShort((short) name.length).putShort((short) 0)
                    .put(name);
            out.writeBytes(local.array());
            out.writeBytes(e.data);
        }

        long centralDirectoryStart = out.size();
        for (int i = 0; i < entries.size(); i++) {
            var e = entries.get(i);
            var name = e.name.getBytes(StandardCharsets.UTF_8);
            var central = ByteBuffer.allocate(46 + name.length + e.centralExtra.length).order(ByteOrder.LITTLE_ENDIAN);
            central.putInt(0x02014b50)
                    .putShort((short) 45).putShort((short) 45) // version made by, needed
                    .putShort((short) 0).putShort((short) 0) // flags, stored
                    .putShort((short) 0).putShort((short) 0) // time, date
                    .putInt(0) // crc
                    .putInt((int) orElse(e.compressedSize, e.data.length))
                    .putInt((int) orElse(e.uncompressedSize, e.data.length))
                    .putShort((short) orElse(e.fileNameLength, name.length))
                    .putShort((short) orElse(e.extraFieldLength, e.centralExtra.length))
                    .putShort((short) orElse(e.fileCommentLength, 0))
                    .putShort((short) 0) // disk number start
                    .putShort((short) 0) // internal attributes
                    .putInt(0) // external attributes
                    .putInt((int) orElse(e.localHeaderOffset, offsets.get(i)))
                    .put(name)
                    .put(e.centralExtra);
            out.writeBytes(central.array());
        }
        long centralDirectorySize = out.size() - centralDirectoryStart;

        var eocd = ByteBuffer.allocate(22).order(ByteOrder.LITTLE_ENDIAN);
        eocd.putInt(0x06054b50)
                .putShort((short) 0).putShort((short) 0)
                .putShort((short) entries.size()).putShort((short) entries.size())
                .putInt((int) centralDirectorySize)
                .putInt((int) centralDirectoryStart)
                .putShort((short) 0);
        out.writeBytes(eocd.array());
        return out.toByteArray();
    }

    private static long orElse(Number override, long dflt) {
        return override == null ? dflt : override.longValue();
    }
}
