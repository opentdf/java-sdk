package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import org.apache.commons.compress.archivers.zip.Zip64Mode;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

public class ZipReaderTest {

    @Test
    public void testReadingExistingZip() throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile("src/test/resources/sample.txt.tdf", "r")) {
            var fileChannel = raf.getChannel();
            ZipReaderTest.testReadingZipChannel(fileChannel, true);
        }
    }

    protected static void testReadingZipChannel(SeekableByteChannel fileChannel, boolean test) throws IOException {
        var zipReader = new ZipReader(fileChannel);
        var entries = zipReader.getEntries();
        if (test) {
            assertThat(entries.size()).isEqualTo(2);
        }
        for (var entry: entries) {
            var stream = new ByteArrayOutputStream();
            if (entry.getName().endsWith(".json")) {
                entry.getData().transferTo(stream);
                var data = stream.toString(StandardCharsets.UTF_8);
                var gson = new Gson();
                var map = gson.fromJson(data, Map.class);
                
                if (test) {
                    assertThat(map.get("encryptionInformation")).isNotNull();
                }
            } else if (!test) {
                entry.getData().transferTo(stream);        // still invoke getData logic
            }
        }
    }

    @Test
    public void testReadingAFileWrittenUsingCommons() throws IOException {
        SeekableInMemoryByteChannel outputChannel = new SeekableInMemoryByteChannel();
        ZipArchiveOutputStream zip = new ZipArchiveOutputStream(outputChannel);
        zip.setUseZip64(Zip64Mode.Always);
        ZipArchiveEntry entry1 = new ZipArchiveEntry("the first entry");
        entry1.setMethod(0);
        zip.putArchiveEntry(entry1);
        new ByteArrayInputStream("this is the first entry contents".getBytes(StandardCharsets.UTF_8)).transferTo(zip);
        zip.closeArchiveEntry();
        ZipArchiveEntry entry2 = new ZipArchiveEntry("the second entry");
        entry2.setMethod(0);
        zip.putArchiveEntry(entry2);
        new ByteArrayInputStream("this is the second entry contents".getBytes(StandardCharsets.UTF_8)).transferTo(zip);
        zip.closeArchiveEntry();
        zip.close();

        SeekableInMemoryByteChannel inputChannel = new SeekableInMemoryByteChannel(outputChannel.array());

        var reader = new ZipReader(inputChannel);

        for (ZipReader.Entry entry: reader.getEntries()) {
            try (var data = entry.getData()) {
                var bytes = new ByteArrayOutputStream();
                data.transferTo(bytes);

                var stringData = bytes.toString(StandardCharsets.UTF_8);
                if (entry.getName().equals("the first entry")) {
                    assertThat(stringData).isEqualTo("this is the first entry contents");
                } else {
                    assertThat(entry.getName()).isEqualTo("the second entry");
                    assertThat(stringData).isEqualTo("this is the second entry contents");
                }
            }
        }
    }

    @Test
    public void testSingleByteReadAdvancesThroughEntry() throws IOException {
        byte[] expected = "contents with distinct bytes".getBytes(StandardCharsets.UTF_8);
        SeekableInMemoryByteChannel outputChannel = new SeekableInMemoryByteChannel();
        ZipArchiveOutputStream zip = new ZipArchiveOutputStream(outputChannel);
        ZipArchiveEntry zipEntry = new ZipArchiveEntry("entry");
        zipEntry.setMethod(0);
        zip.putArchiveEntry(zipEntry);
        zip.write(expected);
        zip.closeArchiveEntry();
        zip.close();

        var reader = new ZipReader(new SeekableInMemoryByteChannel(outputChannel.array()));
        var entry = reader.getEntries().get(0);
        var actual = new ByteArrayOutputStream();
        try (var data = entry.getData()) {
            int next;
            while ((next = data.read()) != -1) {
                actual.write(next);
            }
        }

        assertThat(actual.toByteArray()).isEqualTo(expected);
    }

    @Test
    public void testReadingAndWritingRandomFiles() throws IOException {
        Random r = new Random();
        int numEntries = r.nextInt(500) + 10;
        var testData = IntStream.range(0, numEntries)
                .mapToObj(ignored -> {
                    int fileNameLength = r.nextInt(1000);
                    String name = IntStream.range(0, fileNameLength)
                            .mapToObj(idx -> {
                                var chars = "abcdefghijklmnopqrstuvwxyz ≈ç´ƒ∆∂ßƒåˆß∂øƒ¨åß∂∆˚¬…∆˚¬ˆøπ¨πøƒ∂åß˚¬…∆¬…ˆøåπƒ∆";
                                var randIdx = r.nextInt(chars.length());
                                return chars.substring(randIdx, randIdx + 1);
                            })
                            .collect(Collectors.joining());
                    int fileSize = r.nextInt(3000);
                    byte[] fileContent = new byte[fileSize];
                    r.nextBytes(fileContent);

                    return new Object[] {name, fileContent};
                }).collect(Collectors.toList());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ZipWriter writer = new ZipWriter(out);
        HashMap<String, byte[]> namesToData = new HashMap<>();
        for (var data: testData) {
            var fileName = (String)data[0];
            var content = (byte[])data[1];

            if (namesToData.containsKey(fileName)) {
                continue;
            }

            namesToData.put(fileName, content);

            if (r.nextBoolean()) {
                writer.data(fileName, content);
            } else {
                try (var streamEntry = writer.stream(fileName)) {
                    new ByteArrayInputStream(content).transferTo(streamEntry);
                }
            }
        }

        writer.finish();

        var channel = new SeekableInMemoryByteChannel(out.toByteArray());

        ZipReader reader = new ZipReader(channel);

        for (var entry: reader.getEntries()) {
            assertThat(namesToData).containsKey(entry.getName());
            var zipData = new ByteArrayOutputStream();
            entry.getData().transferTo(zipData);
            assertThat(zipData.toByteArray()).isEqualTo(namesToData.get(entry.getName()));
        }

        assertThat(reader.getEntries().size()).isEqualTo(namesToData.size());
    }

    private static final String PAYLOAD = "a payload long enough to push the manifest along";
    private static final String MANIFEST = "{\"payload\":{\"protocol\":\"zip\"}}";

    /** Sizes of the three trailing records, which are fixed when the archive has no comment. */
    private static final int EOCD_SIZE = 22;
    private static final int ZIP64_EOCD_LOCATOR_SIZE = 20;
    private static final int ZIP64_EOCD_SIZE = 56;

    private static final int EOCD_SIGNATURE = 0x06054b50;
    private static final int ZIP64_EOCD_SIGNATURE = 0x06064b50;

    /**
     * An archive doesn't have to use the central directory offset sentinel to be zip64: one with
     * more than 65,535 entries needs zip64 for its entry count alone, while its central directory
     * still starts below 4 GiB. A reader that looks only at the offset takes the non-zip64 path,
     * believes there are 65,535 entries, and walks off the end of the central directory.
     */
    @Test
    public void testReadingAZip64ArchiveThatOnlyFlagsItsEntryCount() throws IOException {
        assertReadsEveryEntry(keepOnlyTheEntryCountSentinel(zip64Archive()));
    }

    /**
     * A zip64 archive small enough to check here. The lowered writer threshold marks the later
     * entries zip64, so the writer emits a zip64 end of central directory record and fills every
     * end of central directory field with its sentinel.
     */
    private static byte[] zip64Archive() throws IOException {
        var out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out, 8);
        writer.data("small.txt", "tiny".getBytes(StandardCharsets.UTF_8));
        try (var entry = writer.stream("0.payload")) {
            new ByteArrayInputStream(PAYLOAD.getBytes(StandardCharsets.UTF_8)).transferTo(entry);
        }
        writer.data("0.manifest.json", MANIFEST.getBytes(StandardCharsets.UTF_8));
        writer.finish();
        return out.toByteArray();
    }

    /**
     * Rewrites the trailing end of central directory record so the entry count is the only field
     * left holding a sentinel, taking the true size and offset out of the zip64 record that
     * already carries them. The result is still a valid zip64 archive; it just no longer
     * announces itself through the offset, which is the field the reader used to follow.
     */
    private static byte[] keepOnlyTheEntryCountSentinel(byte[] archive) {
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);

        int zip64Eocd = archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE + ZIP64_EOCD_SIZE);
        assertThat(buf.getInt(zip64Eocd)).isEqualTo(ZIP64_EOCD_SIGNATURE);
        long centralDirectorySize = buf.getLong(zip64Eocd + 40);
        long centralDirectoryOffset = buf.getLong(zip64Eocd + 48);

        int eocd = archive.length - EOCD_SIZE;
        assertThat(buf.getInt(eocd)).isEqualTo(EOCD_SIGNATURE);
        buf.putInt(eocd + 12, (int) centralDirectorySize);
        buf.putInt(eocd + 16, (int) centralDirectoryOffset);

        return archive;
    }

    private static void assertReadsEveryEntry(byte[] archive) throws IOException {
        try (var channel = new SeekableInMemoryByteChannel(archive)) {
            assertReadsEveryEntry(channel);
        }

        // and an independent implementation, so this shows the patched archive is well formed
        // rather than just something our own reader happens to tolerate
        try (var channel = new SeekableInMemoryByteChannel(archive)) {
            var zip = new ZipFile.Builder().setSeekableByteChannel(channel).get();
            assertThat(readEntry(zip, "small.txt")).isEqualTo("tiny");
            assertThat(readEntry(zip, "0.payload")).isEqualTo(PAYLOAD);
            assertThat(readEntry(zip, "0.manifest.json")).isEqualTo(MANIFEST);
        }
    }

    /** Our reader alone, for archives or channels an independent implementation can't take. */
    private static void assertReadsEveryEntry(SeekableByteChannel channel) throws IOException {
        var reader = new ZipReader(channel);
        assertThat(reader.getEntries()).hasSize(3);
        assertThat(readEntry(reader, "small.txt")).isEqualTo("tiny");
        assertThat(readEntry(reader, "0.payload")).isEqualTo(PAYLOAD);
        assertThat(readEntry(reader, "0.manifest.json")).isEqualTo(MANIFEST);
    }

    /**
     * An archive missing the trailing records it needs is not a zip, and has to say so rather
     * than fail somewhere downstream. Whether the record is gone, clipped, or the file is shorter
     * than one, the scan finds no acceptable signature within its window.
     */
    @Test
    public void testTruncatedArchiveIsRejected() throws IOException {
        var archive = zip64Archive();

        // the trailing end of central directory record and its locator are gone
        var withoutTrailingRecords =
                Arrays.copyOf(archive, archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE));
        // only the last few bytes of the record are gone
        var clippedRecord = Arrays.copyOf(archive, archive.length - 4);
        // cut down to less than a single end of central directory record
        var shorterThanARecord = Arrays.copyOf(archive, EOCD_SIZE - 1);

        for (var truncated : List.of(withoutTrailingRecords, clippedRecord, shorterThanARecord, new byte[0])) {
            assertThatThrownBy(() -> readArchive(truncated))
                    .withFailMessage("a %d byte truncation should fail the scan", truncated.length)
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("Didn't find the end of central directory");
        }
    }

    /**
     * The end of central directory record claims a zip64 locator that the archive is too short to
     * hold. Reaching for it has to be a zip error rather than an out of range seek.
     */
    @Test
    public void testArchiveTooShortForTheZip64LocatorIsRejected() throws IOException {
        var archive = zip64Archive();
        // drop everything before the trailing records, leaving the end of central directory (which
        // still carries its sentinels) with nothing in front of it
        var truncated = Arrays.copyOfRange(archive, archive.length - EOCD_SIZE, archive.length);

        assertThatThrownBy(() -> readArchive(truncated))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("too small to hold the zip64 end of central directory locator");
    }

    private static void readArchive(byte[] archive) throws IOException {
        try (var channel = new SeekableInMemoryByteChannel(archive)) {
            new ZipReader(channel);
        }
    }

    /**
     * A channel may satisfy a read with fewer bytes than were asked for while more are still
     * available. Every multi-byte field the reader parses has to cope with that, or a valid
     * archive read through such a channel is rejected as corrupt — and {@code loadTDF} takes a
     * caller-supplied channel, so this is reachable from the public API.
     */
    @Test
    public void testArchiveReadThroughAChannelThatReturnsShortReads() throws IOException {
        var archive = zip64Archive();

        for (int maxRead = 1; maxRead <= 8; maxRead++) {
            try (var channel = new ShortReadChannel(new SeekableInMemoryByteChannel(archive), maxRead)) {
                var reader = new ZipReader(channel);
                assertThat(reader.getEntries())
                        .withFailMessage("reading %d byte(s) at a time lost entries", maxRead)
                        .hasSize(3);
                assertThat(readEntry(reader, "0.payload"))
                        .withFailMessage("reading %d byte(s) at a time corrupted the payload", maxRead)
                        .isEqualTo(PAYLOAD);
            }
        }
    }

    /**
     * Trailing bytes push the end of central directory record back from the end of the archive.
     * Everything the reader derives from it — the zip64 locator above all — has to be measured
     * from where the record actually is, not from the end of the file.
     */
    @Test
    public void testZip64ArchiveWithTrailingDataStillReads() throws IOException {
        var archive = zip64Archive();
        var padded = Arrays.copyOf(archive, archive.length + 100);

        assertReadsEveryEntry(padded);
    }

    /**
     * The scan only looks back as far as the longest possible comment, 65,535 bytes; trailing data
     * is tolerated only within that same window. Beyond it an archive is not one we can read, and
     * saying so immediately is the point: an unbounded scan reads its way back through the whole
     * file a byte at a time before reaching the same conclusion.
     */
    @Test
    public void testEndOfCentralDirectoryPushedBeyondTheCommentLimitIsRejected() throws IOException {
        var archive = zip64Archive();
        var padded = Arrays.copyOf(archive, archive.length + 0xFFFF + 1);

        assertThatThrownBy(() -> readArchive(padded))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("Didn't find the end of central directory");
    }

    /**
     * The zip64 locator's pointer to the zip64 end of central directory record is a 64-bit value
     * taken straight from the archive, so a corrupt one can point anywhere. Following it has to
     * be a zip error rather than an out of range seek.
     */
    @Test
    public void testZip64LocatorPointingOutsideTheArchiveIsRejected() throws IOException {
        // the locator sits between the zip64 end of central directory record and the trailing
        // end of central directory record; its pointer is 8 bytes in, after the signature and
        // the disk number
        int pointer = zip64Archive().length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE) + 8;

        for (long badOffset : new long[] { -1L, Long.MIN_VALUE, 1L << 40 }) {
            var archive = zip64Archive();
            ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN).putLong(pointer, badOffset);

            assertThatThrownBy(() -> readArchive(archive))
                    .withFailMessage("an offset of %d should be rejected as a zip error", badOffset)
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("outside this");
        }
    }

    /**
     * The same for the central directory offset the zip64 record carries, which is the other
     * 64-bit offset the reader seeks to.
     */
    @Test
    public void testZip64CentralDirectoryOffsetOutsideTheArchiveIsRejected() throws IOException {
        var archive = zip64Archive();
        int zip64Eocd = archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE + ZIP64_EOCD_SIZE);
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        assertThat(buf.getInt(zip64Eocd)).isEqualTo(ZIP64_EOCD_SIGNATURE);
        buf.putLong(zip64Eocd + 48, -1L);

        assertThatThrownBy(() -> readArchive(archive))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("outside this");
    }

    /**
     * The largest comment the format allows pushes the end of central directory record as far
     * back as it can go. That is the edge of the scan window, and the record still has to be
     * found there — and the zip64 locator in front of it, measured from the record rather than
     * from the end of the archive.
     */
    @Test
    public void testZip64ArchiveWithTheLongestPossibleCommentStillReads() throws IOException {
        var comment = new byte[0xFFFF];
        Arrays.fill(comment, (byte) 'c');

        assertReadsEveryEntry(withComment(zip64Archive(), comment));
    }

    /**
     * A comment can contain anything, including the end of central directory signature. Scanning
     * backwards meets that one first. Here it is passed over because the comment it would carry
     * runs off the end of the archive, which the real record's does not; see
     * {@link #testSignatureWithAPlausibleCommentLengthIsNotMistakenForTheRecord} for one whose
     * comment fits.
     */
    @Test
    public void testSignatureInsideTheCommentIsNotMistakenForTheRecord() throws IOException {
        var comment = new byte[64];
        Arrays.fill(comment, (byte) 0xFF); // so the decoy's own comment length reads as 0xFFFF
        ByteBuffer.wrap(comment).order(ByteOrder.LITTLE_ENDIAN).putInt(0, EOCD_SIGNATURE);

        // an independent reader may take the decoy for the record, so this one is ours alone
        try (var channel = new SeekableInMemoryByteChannel(withComment(zip64Archive(), comment))) {
            assertReadsEveryEntry(channel);
        }
    }

    /**
     * A stray signature whose declared comment fits in the archive gets past the comment check, so
     * the central directory it describes has to give it away: it never ends where the stray
     * record starts. Covers a zero-filled record, which would read as an empty archive; a copy of
     * the real record, which for a zip64 archive sends the reader looking for a locator that isn't
     * there; and a copy claiming one entry, which would read as an archive missing two. Each one
     * goes in a comment with room to spare, in a comment it fills exactly, and in trailing data.
     */
    @Test
    public void testSignatureWithAPlausibleCommentLengthIsNotMistakenForTheRecord() throws IOException {
        for (var base : List.of(plainArchive(), zip64Archive())) {
            var empty = new byte[EOCD_SIZE];
            ByteBuffer.wrap(empty).order(ByteOrder.LITTLE_ENDIAN).putInt(0, EOCD_SIGNATURE);
            var copy = Arrays.copyOfRange(base, base.length - EOCD_SIZE, base.length);
            var oneEntry = copy.clone();
            ByteBuffer.wrap(oneEntry).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) 1).putShort(10, (short) 1);

            for (var decoy : List.of(empty, copy, oneEntry)) {
                var roomy = Arrays.copyOf(decoy, 64);
                var trailing = Arrays.copyOf(base, base.length + roomy.length);
                System.arraycopy(roomy, 0, trailing, base.length, roomy.length);

                for (var archive : List.of(withComment(base, roomy), withComment(base, decoy), trailing)) {
                    assertThatCode(() -> {
                        try (var channel = new SeekableInMemoryByteChannel(archive)) {
                            assertReadsEveryEntry(channel);
                        }
                    }).as("a %d byte archive with a decoy record", archive.length).doesNotThrowAnyException();
                }
            }
        }
    }

    /** A record whose comment was cut short isn't the end of a whole archive. */
    @Test
    public void testRecordWhoseCommentRunsPastTheEndIsRejected() throws IOException {
        var withFullComment = withComment(zip64Archive(), new byte[10]);
        var truncated = Arrays.copyOf(withFullComment, withFullComment.length - 5);

        assertThatThrownBy(() -> readArchive(truncated))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("Didn't find the end of central directory");
    }

    /**
     * Gives the trailing end of central directory record a comment. Assumes, as is true of
     * everything our writer produces, that the archive doesn't already have one.
     */
    private static byte[] withComment(byte[] archive, byte[] comment) {
        var result = Arrays.copyOf(archive, archive.length + comment.length);
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)
                .putShort(archive.length - Short.BYTES, (short) comment.length);
        System.arraycopy(comment, 0, result, archive.length, comment.length);
        return result;
    }

    /**
     * A channel is allowed to return zero bytes without being at the end of the stream; only
     * {@code -1} means that. An empty read has to be retried, not taken for the end of the
     * archive.
     */
    @Test
    public void testArchiveReadThroughAChannelThatReturnsEmptyReads() throws IOException {
        try (var channel = new StallingChannel(new SeekableInMemoryByteChannel(zip64Archive()), 1)) {
            assertReadsEveryEntry(channel);
        }
    }

    /**
     * But a channel that never returns anything has to fail, rather than leave the reader
     * spinning on it — whether it stops before the archive is opened or partway through an entry.
     */
    @Test
    public void testChannelThatStopsReturningDataFails() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            try (var channel = new StallingChannel(new SeekableInMemoryByteChannel(zip64Archive()), 0)) {
                channel.stalled = true;
                assertThatThrownBy(() -> new ZipReader(channel))
                        .isInstanceOf(IOException.class)
                        .hasMessageContaining("no data");
            }

            // getData() reads the local header, so the stall has to start after it returns to
            // reach the stream itself: once for a block read, once for a single byte
            try (var channel = new StallingChannel(new SeekableInMemoryByteChannel(zip64Archive()), 0);
                 var data = new ZipReader(channel).getEntries().get(0).getData()) {
                channel.stalled = true;
                assertThatThrownBy(() -> data.read(new byte[4]))
                        .isInstanceOf(IOException.class)
                        .hasMessageContaining("no data");
            }
            try (var channel = new StallingChannel(new SeekableInMemoryByteChannel(zip64Archive()), 0);
                 var data = new ZipReader(channel).getEntries().get(0).getData()) {
                channel.stalled = true;
                assertThatThrownBy(data::read)
                        .isInstanceOf(IOException.class)
                        .hasMessageContaining("no data");
            }
        });
    }

    /**
     * The zip64 entry count is a 64-bit value taken straight from the archive. One that is
     * negative would read as an empty archive, and one too large for the central directory to
     * hold would send the reader past its end; both have to be zip errors instead.
     */
    @Test
    public void testZip64EntryCountTheCentralDirectoryCannotHoldIsRejected() throws IOException {
        for (long badCount : new long[] { -1L, Long.MIN_VALUE, 1_000_000L }) {
            var archive = zip64Archive();
            int zip64Eocd = archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE + ZIP64_EOCD_SIZE);
            var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
            assertThat(buf.getInt(zip64Eocd)).isEqualTo(ZIP64_EOCD_SIGNATURE);
            buf.putLong(zip64Eocd + 32, badCount);

            assertThatThrownBy(() -> readArchive(archive))
                    .withFailMessage("an entry count of %d should be rejected as a zip error", badCount)
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("can hold at most");
        }
    }

    /**
     * A zip64 entry size is unsigned on the wire, but one that reads as a negative {@code long}
     * describes more than any archive can hold. Left alone it reads as an empty entry, so a
     * corrupt size would silently drop the entry's data instead of failing.
     */
    @Test
    public void testZip64EntrySizeThatReadsAsNegativeIsRejected() throws IOException {
        for (long badSize : new long[] { -1L, Long.MIN_VALUE }) {
            var archive = zip64Archive();
            var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
            int zip64Eocd = archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE + ZIP64_EOCD_SIZE);
            assertThat(buf.getInt(zip64Eocd)).isEqualTo(ZIP64_EOCD_SIGNATURE);

            // walk the central directory to the streamed entry, which the writer always marks zip64
            int header = (int) buf.getLong(zip64Eocd + 48);
            while (!new String(archive, header + 46, buf.getShort(header + 28), StandardCharsets.UTF_8)
                    .equals("0.payload")) {
                header += 46 + buf.getShort(header + 28) + buf.getShort(header + 30) + buf.getShort(header + 32);
            }
            int extraField = header + 46 + buf.getShort(header + 28);
            assertThat(buf.getShort(extraField)).as("zip64 extra field id").isEqualTo((short) 1);
            // the original size is the first value in the field, after its id and data size
            buf.putLong(extraField + 4, badSize);

            assertThatThrownBy(() -> readArchive(archive))
                    .withFailMessage("a size of %d should be rejected as a zip error", badSize)
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining(Long.toUnsignedString(badSize));
        }
    }

    /**
     * A zip64 central directory size that reads as negative, with an offset past the record it
     * ends at so that the two still add up to that record's position. It describes a directory
     * that starts after it ends, and has to be rejected rather than read.
     */
    @Test
    public void testZip64CentralDirectorySizeThatReadsAsNegativeIsRejected() throws IOException {
        var archive = zip64Archive();
        int zip64Eocd = archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE + ZIP64_EOCD_SIZE);
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        assertThat(buf.getInt(zip64Eocd)).isEqualTo(ZIP64_EOCD_SIGNATURE);
        long offset = archive.length - 1;
        buf.putLong(zip64Eocd + 40, zip64Eocd - offset);
        buf.putLong(zip64Eocd + 48, offset);

        assertThatThrownBy(() -> readArchive(archive))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining(Long.toUnsignedString(zip64Eocd - offset));
    }

    /** The same bounds check, on the 32-bit offset of an archive that isn't zip64 at all. */
    @Test
    public void testCentralDirectoryOffsetOutsideTheArchiveIsRejected() throws IOException {
        int length = plainArchive().length;
        for (long badOffset : new long[] { length, 0xFFFFFFFEL }) {
            var archive = plainArchive();
            ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(archive.length - EOCD_SIZE + 16, (int) badOffset);

            assertThatThrownBy(() -> readArchive(archive))
                    .withFailMessage("an offset of %d should be rejected as a zip error", badOffset)
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("outside this");
        }
    }

    /**
     * An archive with no entries has nothing but its end of central directory record, and its
     * central directory offset points right at it. That is still inside the archive.
     */
    @Test
    public void testEmptyArchiveReads() throws IOException {
        var out = new ByteArrayOutputStream();
        new ZipWriter(out).finish();

        try (var channel = new SeekableInMemoryByteChannel(out.toByteArray())) {
            assertThat(new ZipReader(channel).getEntries()).isEmpty();
        }
    }

    /** A central directory that ends partway through a filename is a zip error like any other. */
    @Test
    public void testCentralDirectoryFilenameRunningPastTheEndIsRejected() throws IOException {
        var archive = plainArchive();
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        int centralDirectory = buf.getInt(archive.length - EOCD_SIZE + 16);
        buf.putShort(centralDirectory + 28, (short) 0x7000);

        assertThatThrownBy(() -> readArchive(archive))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("byte filename");
    }

    /**
     * An entry whose data runs past the end of the archive is truncated, and reading it has to
     * say so rather than end the stream early and hand back a short entry as if it were whole.
     */
    @Test
    public void testEntryRunningPastTheEndOfTheArchiveFailsToRead() throws IOException {
        var archive = plainArchive();
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        int centralDirectory = buf.getInt(archive.length - EOCD_SIZE + 16);
        // small.txt comes first; claim it is far bigger than the archive
        buf.putInt(centralDirectory + 24, 1_000_000);

        try (var channel = new SeekableInMemoryByteChannel(archive)) {
            var reader = new ZipReader(channel);
            assertThatThrownBy(() -> readEntry(reader, "small.txt"))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[small.txt]")
                    .hasMessageContaining("1000000");

            // and a byte at a time, which takes a different path through the stream
            var entry = reader.getEntries().get(0);
            assertThatThrownBy(() -> drainByteAtATime(entry))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[small.txt]");
        }
    }

    /**
     * {@link java.io.InputStream} requires a zero-length read to return 0, even at the end of the
     * stream. Passed through to the channel, it would read nothing every time and trip the
     * stalled-channel check on a valid archive.
     */
    @Test
    public void testZeroLengthReadReturnsZero() throws IOException {
        try (var channel = new SeekableInMemoryByteChannel(plainArchive())) {
            var entry = new ZipReader(channel).getEntries().get(0);
            try (var data = entry.getData()) {
                var buf = new byte[4];
                assertThat(data.read(buf, 0, 0)).isZero();
                assertThat(data.read()).isEqualTo('t');
                assertThat(data.read(buf, 0, 0)).isZero();
                assertThat(data.read(buf, 0, 4)).isEqualTo(3);
                // the entry is used up, but a zero-length read is still 0 rather than -1
                assertThat(data.read(buf, 0, 0)).isZero();
                assertThat(data.read(buf, 0, 4)).isEqualTo(-1);
            }
        }
    }

    /**
     * An end of central directory record that claims zip64 when nothing in front of it is a
     * locator. The locator is looked for immediately before the record, and what is there instead
     * has to be reported as a bad signature at that offset.
     */
    @Test
    public void testMissingZip64LocatorIsRejected() throws IOException {
        var archive = plainArchive();
        ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(archive.length - EOCD_SIZE + 16, 0xFFFFFFFF);
        int locatorStart = archive.length - EOCD_SIZE - ZIP64_EOCD_LOCATOR_SIZE;

        assertThatThrownBy(() -> readArchive(archive))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("locator")
                .hasMessageContaining("offset " + locatorStart);
    }

    /**
     * A locator pointer that stays inside the archive but lands on something other than the zip64
     * end of central directory record. The bounds check passes, so the signature check is all
     * that stands between the reader and a misparse.
     */
    @Test
    public void testZip64LocatorPointingAtTheWrongRecordIsRejected() throws IOException {
        var archive = zip64Archive();
        int pointer = archive.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE) + 8;
        // offset 0 holds the first local file header
        ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN).putLong(pointer, 0L);

        assertThatThrownBy(() -> readArchive(archive))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("0x" + Integer.toHexString(0x04034b50));
    }

    /**
     * A channel whose size claims more bytes than it holds. Every offset the scan probes should
     * have a whole record after it, so running out of data there is a zip error, not a miss.
     */
    @Test
    public void testChannelSmallerThanItsReportedSizeIsRejected() throws IOException {
        var archive = plainArchive();
        long claimedSize = archive.length + 30L;
        try (var channel = new DelegatingChannel(new SeekableInMemoryByteChannel(archive)) {
            @Override
            public long size() {
                return claimedSize;
            }
        }) {
            assertThatThrownBy(() -> new ZipReader(channel))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining(Long.toString(claimedSize));
        }
    }

    /** Every hostile shape fails with {@link InvalidZipException}, without hanging. */
    @Test
    public void testHostileCentralDirectoryFieldsAreRejected() {
        HostileZips.hostileShapes().forEach((shape, hostile) -> {
            var archive = HostileZips.tdfWith(MANIFEST, hostile);
            // reading every entry, not just the directory, so a shape that only fails once its
            // data is read is caught too
            assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
                    assertThatThrownBy(() -> testReadingZipChannel(new SeekableInMemoryByteChannel(archive), false))
                            .as(shape).isInstanceOf(InvalidZipException.class),
                    shape);
        });
    }

    /**
     * The last central directory header claims a filename longer than the one it holds, so the
     * name runs into the end of central directory record. Checked only against the end of the
     * archive, that record's bytes would come back as part of the entry name.
     */
    @Test
    public void testFilenameRunningPastTheCentralDirectoryIsRejected() {
        var archive = HostileZips.tdfWith(MANIFEST, e -> e.fileNameLength = e.name.length() + 10);

        assertThatThrownBy(() -> readArchive(archive))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("past the end of the central directory");
    }

    /**
     * A central directory whose declared size runs into the record after it, in both a plain
     * archive and a zip64 one. With no other candidate record to fall back on, the scan reports
     * why it passed over the real one.
     */
    @Test
    public void testCentralDirectorySizeRunningIntoTheNextRecordIsRejected() throws IOException {
        var plain = plainArchive();
        var plainBuf = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN);
        int sizeField = plain.length - EOCD_SIZE + 12;
        plainBuf.putInt(sizeField, plainBuf.getInt(sizeField) + 1);

        var zip64 = zip64Archive();
        int zip64Eocd = zip64.length - (EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE + ZIP64_EOCD_SIZE);
        var zip64Buf = ByteBuffer.wrap(zip64).order(ByteOrder.LITTLE_ENDIAN);
        assertThat(zip64Buf.getInt(zip64Eocd)).isEqualTo(ZIP64_EOCD_SIGNATURE);
        zip64Buf.putLong(zip64Eocd + 40, zip64Buf.getLong(zip64Eocd + 40) + 1);

        for (var archive : List.of(plain, zip64)) {
            assertThatThrownBy(() -> readArchive(archive))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("which does not end where that record starts");
        }
    }

    /** The hand-built archives the hostile shapes start from are valid until a shape is applied. */
    @Test
    public void testHandBuiltArchiveReads() throws IOException {
        var archive = HostileZips.tdfWith(MANIFEST, e -> { });
        try (var channel = new SeekableInMemoryByteChannel(archive)) {
            var reader = new ZipReader(channel);
            assertThat(readEntry(reader, "0.manifest.json")).isEqualTo(MANIFEST);
            assertThat(readEntry(reader, "0.payload")).isEqualTo("payload bytes");
        }
    }

    /**
     * A zip64 record whose values are all within range is still honoured, after an unrelated
     * record and followed by a few bytes too short to be a record, which readers ignore.
     */
    @Test
    public void testZip64ExtraFieldAmongOtherRecordsStillReads() throws IOException {
        var archive = HostileZips.tdfWith(MANIFEST, e -> {
            e.uncompressedSize = 0xFFFFFFFFL;
            e.compressedSize = 0xFFFFFFFFL;
            e.localHeaderOffset = 0xFFFFFFFFL;
            long offset = "0.payload".length() + 30 + "payload bytes".length();
            e.centralExtra = HostileZips.concat(
                    HostileZips.extraRecord(0xCAFE, 2, new byte[2]),
                    HostileZips.extraRecord(0x0001, 24, HostileZips.longs(e.data.length, e.data.length, offset)),
                    new byte[3]);
        });
        try (var channel = new SeekableInMemoryByteChannel(archive)) {
            var reader = new ZipReader(channel);
            assertThat(readEntry(reader, "0.manifest.json")).isEqualTo(MANIFEST);
            assertThat(readEntry(reader, "0.payload")).isEqualTo("payload bytes");
        }
    }

    /** The same three entries as {@link #zip64Archive()}, written without anything zip64. */
    private static byte[] plainArchive() throws IOException {
        var out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out);
        writer.data("small.txt", "tiny".getBytes(StandardCharsets.UTF_8));
        writer.data("0.payload", PAYLOAD.getBytes(StandardCharsets.UTF_8));
        writer.data("0.manifest.json", MANIFEST.getBytes(StandardCharsets.UTF_8));
        writer.finish();
        var archive = out.toByteArray();
        assertReadsEveryEntry(archive);
        return archive;
    }

    /** Hands back at most {@code maxRead} bytes per read, as a channel is permitted to do. */
    private static final class ShortReadChannel extends DelegatingChannel {
        private final int maxRead;

        ShortReadChannel(SeekableByteChannel delegate, int maxRead) {
            super(delegate);
            this.maxRead = maxRead;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            if (!dst.hasRemaining()) {
                return 0;
            }
            int limit = dst.limit();
            dst.limit(dst.position() + Math.min(maxRead, dst.remaining()));
            try {
                return delegate.read(dst);
            } finally {
                dst.limit(limit);
            }
        }
    }

    /**
     * Returns nothing {@code emptyReadsBeforeEachRead} times before every read that does return
     * data, as a non-blocking channel is permitted to do, and nothing at all once {@code stalled}.
     */
    private static final class StallingChannel extends DelegatingChannel {
        private final int emptyReadsBeforeEachRead;
        private int emptyReadsSoFar;
        volatile boolean stalled;

        StallingChannel(SeekableByteChannel delegate, int emptyReadsBeforeEachRead) {
            super(delegate);
            this.emptyReadsBeforeEachRead = emptyReadsBeforeEachRead;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            if (stalled) {
                return 0;
            }
            if (emptyReadsSoFar < emptyReadsBeforeEachRead) {
                emptyReadsSoFar++;
                return 0;
            }
            emptyReadsSoFar = 0;
            return delegate.read(dst);
        }
    }

    private static class DelegatingChannel implements SeekableByteChannel {
        protected final SeekableByteChannel delegate;

        DelegatingChannel(SeekableByteChannel delegate) {
            this.delegate = delegate;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            return delegate.read(dst);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            return delegate.write(src);
        }

        @Override
        public long position() throws IOException {
            return delegate.position();
        }

        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            delegate.position(newPosition);
            return this;
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }

        @Override
        public boolean isOpen() {
            return delegate.isOpen();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    private static String readEntry(ZipReader reader, String name) throws IOException {
        var entry = reader.getEntries().stream()
                .filter(e -> e.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no entry named " + name));
        var data = new ByteArrayOutputStream();
        entry.getData().transferTo(data);
        return data.toString(StandardCharsets.UTF_8);
    }

    private static void drainByteAtATime(ZipReader.Entry entry) throws IOException {
        try (var data = entry.getData()) {
            while (data.read() != -1) {
                // drain
            }
        }
    }

    private static String readEntry(ZipFile zip, String name) throws IOException {
        var data = new ByteArrayOutputStream();
        zip.getInputStream(zip.getEntry(name)).transferTo(data);
        return data.toString(StandardCharsets.UTF_8);
    }
}
