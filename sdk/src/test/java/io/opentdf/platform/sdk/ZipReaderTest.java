package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import org.apache.commons.compress.archivers.zip.Zip64Mode;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.zip.DataFormatException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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

    // OpenTDF writers store entries uncompressed, but other TDF writers may deflate them. The
    // reader has to inflate method 8, refuse every other method by name, and hold inflation to
    // the uncompressed size the central directory declares.

    @Test
    public void testReadingDeflatedEntries() throws IOException {
        byte[] first = compressibleBytes(10_000);
        byte[] second = compressibleBytes(3_000);
        byte[] archive = zipOf(Zip64Mode.Never, deflated("first", first), deflated("second", second));
        assertThat(compressionMethodOf(archive, "first")).isEqualTo(ZipEntry.DEFLATED);
        assertThat(compressedSizeOf(archive, "first")).isLessThan(first.length);

        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        assertThat(readEntryBytes(reader, "first")).isEqualTo(first);
        assertThat(readEntryBytes(reader, "second")).isEqualTo(second);
    }

    @Test
    public void testReadingStoredAndDeflatedEntriesInOneArchive() throws IOException {
        byte[] storedContent = compressibleBytes(5_000);
        byte[] deflatedContent = compressibleBytes(7_000);
        byte[] archive = zipOf(Zip64Mode.Never,
                stored("stored", storedContent),
                deflated("deflated", deflatedContent),
                stored("empty stored", new byte[0]),
                deflated("empty deflated", new byte[0]));
        assertThat(compressionMethodOf(archive, "stored")).isEqualTo(ZipEntry.STORED);
        assertThat(compressionMethodOf(archive, "deflated")).isEqualTo(ZipEntry.DEFLATED);
        assertThat(compressionMethodOf(archive, "empty deflated")).isEqualTo(ZipEntry.DEFLATED);

        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        assertThat(readEntryBytes(reader, "stored")).isEqualTo(storedContent);
        assertThat(readEntryBytes(reader, "deflated")).isEqualTo(deflatedContent);
        assertThat(readEntryBytes(reader, "empty stored")).isEmpty();
        assertThat(readEntryBytes(reader, "empty deflated")).isEmpty();
    }

    /** With zip64 forced on, every size in the central directory lives in the zip64 extra field. */
    @Test
    public void testReadingDeflatedZip64Entries() throws IOException {
        byte[] content = compressibleBytes(20_000);
        byte[] small = compressibleBytes(10);
        byte[] archive = zipOf(Zip64Mode.Always, deflated("big", content), stored("small", small));

        long expectedCompressedSize;
        try (var zip = new ZipFile.Builder().setSeekableByteChannel(new SeekableInMemoryByteChannel(archive)).get()) {
            expectedCompressedSize = zip.getEntry("big").getCompressedSize();
        }
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));
        var entry = entryNamed(reader, "big");

        assertThat(entry.getCompressionMethod()).isEqualTo(ZipEntry.DEFLATED);
        assertThat(entry.getCompressedSize()).isEqualTo(expectedCompressedSize).isLessThan(content.length);
        assertThat(entry.getUncompressedSize()).isEqualTo(content.length);
        assertThat(readEntryBytes(reader, "big")).isEqualTo(content);
        assertThat(readEntryBytes(reader, "small")).isEqualTo(small);
    }

    /** A stored entry keeps both sizes too, and they are equal. */
    @Test
    public void testStoredEntryReportsItsSizes() throws IOException {
        byte[] content = compressibleBytes(1_234);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(zipOf(Zip64Mode.Never, stored("entry", content))));
        var entry = entryNamed(reader, "entry");

        assertThat(entry.getCompressionMethod()).isEqualTo(ZipEntry.STORED);
        assertThat(entry.getCompressedSize()).isEqualTo(content.length);
        assertThat(entry.getUncompressedSize()).isEqualTo(content.length);
    }

    /**
     * A streaming writer such as {@link ZipOutputStream} does not know a deflated entry's sizes
     * until after its data, so it leaves zeros in the local header and puts the sizes in a data
     * descriptor and the central directory. The reader must take them from the central directory.
     */
    @Test
    public void testReadingADeflatedEntryWrittenWithADataDescriptor() throws IOException {
        byte[] content = compressibleBytes(9_000);
        var out = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(out)) {
            var entry = new ZipEntry("streamed");
            entry.setMethod(ZipEntry.DEFLATED);
            zip.putNextEntry(entry);
            zip.write(content);
            zip.closeEntry();
        }
        byte[] archive = out.toByteArray();
        int localHeader = (int) localHeaderOffsetOf(archive, "streamed");
        assertThat(ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN).getInt(localHeader + LFH_COMPRESSED_SIZE))
                .withFailMessage("the fixture should leave the local header sizes unset")
                .isZero();

        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        assertThat(readEntryBytes(reader, "streamed")).isEqualTo(content);
    }

    @Test
    public void testSingleByteReadsThroughADeflatedEntry() throws IOException {
        byte[] content = compressibleBytes(2_000);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(zipOf(Zip64Mode.Never, deflated("entry", content))));
        var actual = new ByteArrayOutputStream();
        try (var data = entryNamed(reader, "entry").getData()) {
            int next;
            while ((next = data.read()) != -1) {
                actual.write(next);
            }
        }

        assertThat(actual.toByteArray()).isEqualTo(content);
    }

    /**
     * Entries share the archive's channel, and a TDF reader keeps the payload stream open while
     * it reads the manifest, so each deflated stream has to find its own place in the archive on
     * every read rather than trusting where the channel was left.
     */
    @Test
    public void testInterleavedReadsOfDeflatedEntries() throws IOException {
        byte[] first = randomBytes(50_000, 1);
        byte[] second = compressibleBytes(30_000);
        byte[] archive = zipOf(Zip64Mode.Never, deflated("first", first), deflated("second", second));
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        var firstOut = new ByteArrayOutputStream();
        var secondOut = new ByteArrayOutputStream();
        try (var firstData = entryNamed(reader, "first").getData();
             var secondData = entryNamed(reader, "second").getData()) {
            byte[] buf = new byte[777];
            boolean firstDone = false;
            boolean secondDone = false;
            while (!firstDone || !secondDone) {
                firstDone = firstDone || copyOnce(firstData, buf, firstOut);
                secondDone = secondDone || copyOnce(secondData, buf, secondOut);
            }
        }

        assertThat(firstOut.toByteArray()).isEqualTo(first);
        assertThat(secondOut.toByteArray()).isEqualTo(second);
    }

    /**
     * 12 is bzip2, 9 deflate64, 14 LZMA, 93 zstd and 99 the AE-x encryption marker: real methods,
     * none of which this reader implements. 0xFFFF checks the method is read unsigned.
     */
    @ParameterizedTest
    @ValueSource(ints = { 1, 9, 12, 14, 93, 99, 0xFFFF })
    public void testUnsupportedCompressionMethodIsRejectedByName(int method) throws IOException {
        byte[] archive = withCompressionMethod(
                zipOf(Zip64Mode.Never, stored("0.payload", compressibleBytes(100))), "0.payload", method);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));
        var entry = entryNamed(reader, "0.payload");

        assertThatThrownBy(entry::getData)
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("[0.payload]")
                .hasMessageContaining("unsupported compression method " + method);
    }

    /** Refused only when read, so an archive can still be listed and its other entries read. */
    @Test
    public void testUnsupportedMethodOnOneEntryDoesNotAffectTheOthers() throws IOException {
        byte[] good = compressibleBytes(500);
        byte[] archive = withCompressionMethod(
                zipOf(Zip64Mode.Never, deflated("good", good), stored("bad", compressibleBytes(100))), "bad", 12);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        assertThat(reader.getEntries()).extracting(ZipReader.Entry::getName).containsExactly("good", "bad");
        assertThat(readEntryBytes(reader, "good")).isEqualTo(good);
        var bad = entryNamed(reader, "bad");
        assertThatThrownBy(bad::getData).isInstanceOf(InvalidZipException.class);
    }

    /**
     * The declared uncompressed size bounds inflation: the reader hands back exactly that many
     * bytes, never writes past them into the caller's buffer, and then refuses the entry because
     * the deflate stream holds more.
     */
    @ParameterizedTest
    @ValueSource(longs = { 0, 1, 100, 9_999 })
    public void testDeflatedEntryLargerThanDeclaredIsRejected(long declared) throws IOException {
        byte[] content = compressibleBytes(10_000);
        byte[] archive = withDeclaredUncompressedSize(
                zipOf(Zip64Mode.Never, deflated("entry", content)), "entry", declared);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        var delivered = new ByteArrayOutputStream();
        try (var data = entryNamed(reader, "entry").getData()) {
            assertThatThrownBy(() -> drainIntoOversizedBuffer(data, content.length * 2, delivered))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[entry]")
                    .hasMessageContaining("more data than its declared uncompressed size of " + declared);
        }

        assertThat(delivered.toByteArray()).isEqualTo(Arrays.copyOf(content, (int) declared));
    }

    /**
     * Reads {@code in} to the end through a buffer of {@code bufferSize} bytes, failing if a read
     * writes into the buffer past the count it returns.
     */
    private static void drainIntoOversizedBuffer(InputStream in, int bufferSize, ByteArrayOutputStream out)
            throws IOException {
        final byte untouched = 0x5A;
        byte[] buf = new byte[bufferSize];
        Arrays.fill(buf, untouched);
        int n;
        while ((n = in.read(buf, 0, buf.length)) != -1) {
            out.write(buf, 0, n);
            for (int i = n; i < buf.length; i++) {
                if (buf[i] != untouched) {
                    throw new AssertionError("wrote past the " + n + " bytes it returned");
                }
            }
            Arrays.fill(buf, 0, n, untouched);
        }
    }

    /**
     * A highly compressible entry that understates its size is the shape of a zip bomb. However
     * far it would expand, the reader delivers only the declared size before refusing it.
     */
    @Test
    public void testZipBombIsStoppedAtTheDeclaredSize() throws IOException {
        byte[] bomb = new byte[16 * 1024 * 1024];
        byte[] archive = zipOf(Zip64Mode.Never, deflated("bomb", bomb));
        assertThat(archive.length).isLessThan(bomb.length / 500);
        archive = withDeclaredUncompressedSize(archive, "bomb", 1024);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        var delivered = new ByteArrayOutputStream();
        try (var data = entryNamed(reader, "bomb").getData()) {
            assertThatThrownBy(() -> data.transferTo(delivered))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[bomb]");
        }

        assertThat(delivered.size()).isEqualTo(1024);
    }

    /** The floor of the deflated size budget: 10 MiB. */
    private static final int BUDGET_FLOOR = 10 * 1024 * 1024;

    /**
     * Inflation stops at the declared size, so the declaration itself has a budget: a deflated
     * entry may not claim more than the larger of the archive's length and 10 MiB. 16 MiB of zeros
     * deflates to about 16 KiB, so without that budget this archive would expand a thousandfold.
     * It is refused before a stream exists, so nothing is inflated.
     */
    @Test
    public void testDeflatedEntryDeclaringMoreThanTheBudgetIsRejectedBeforeInflating() throws IOException {
        byte[] bomb = new byte[16 * 1024 * 1024];
        byte[] archive = zipOf(Zip64Mode.Never, deflated("manifest.json", bomb));
        assertThat(archive.length).isLessThan(64 * 1024);
        var entry = entryNamed(new ZipReader(new SeekableInMemoryByteChannel(archive)), "manifest.json");
        int inflatersBefore = ZipReader.inflatersCreated();

        assertThatThrownBy(entry::getData)
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("[manifest.json]")
                .hasMessageContaining("uncompressed size of " + bomb.length + " bytes")
                .hasMessageContaining("budget of " + BUDGET_FLOOR + " bytes");
        assertThat(ZipReader.inflatersCreated()).isEqualTo(inflatersBefore);
    }

    /** A small archive may still hold a deflated entry right up to the floor. */
    @Test
    public void testDeflatedEntryDeclaringExactlyTheBudgetFloorIsRead() throws IOException {
        byte[] zeros = new byte[BUDGET_FLOOR];
        byte[] archive = zipOf(Zip64Mode.Never, deflated("entry", zeros));
        assertThat(archive.length).isLessThan(BUDGET_FLOOR);

        assertThat(readEntryBytes(new ZipReader(new SeekableInMemoryByteChannel(archive)), "entry")).isEqualTo(zeros);
    }

    /** Past the floor the budget is the archive's length, however the archive came to be that long. */
    @Test
    public void testDeflatedSizeBudgetGrowsWithTheArchive() throws IOException {
        byte[] padding = randomBytes(BUDGET_FLOOR + 1024 * 1024, 3);
        byte[] zeros = new byte[BUDGET_FLOOR + 512 * 1024];
        byte[] archive = zipOf(Zip64Mode.Never, stored("padding", padding), deflated("entry", zeros));
        assertThat(archive.length).isGreaterThan(zeros.length);

        assertThat(readEntryBytes(new ZipReader(new SeekableInMemoryByteChannel(archive)), "entry")).isEqualTo(zeros);

        byte[] overBudget = withDeclaredUncompressedSize(archive, "entry", archive.length + 1L);
        var entry = entryNamed(new ZipReader(new SeekableInMemoryByteChannel(overBudget)), "entry");
        assertThatThrownBy(entry::getData)
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("[entry]")
                .hasMessageContaining("uncompressed size of " + (archive.length + 1L) + " bytes")
                .hasMessageContaining("budget of " + archive.length + " bytes");
    }

    @ParameterizedTest
    @ValueSource(longs = { 1, 2, 5_000 })
    public void testDeflatedEntrySmallerThanDeclaredIsRejected(long extra) throws IOException {
        byte[] content = compressibleBytes(10_000);
        long declared = content.length + extra;
        byte[] archive = withDeclaredUncompressedSize(
                zipOf(Zip64Mode.Never, deflated("entry", content)), "entry", declared);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        var delivered = new ByteArrayOutputStream();
        try (var data = entryNamed(reader, "entry").getData()) {
            assertThatThrownBy(() -> data.transferTo(delivered))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[entry]")
                    .hasMessageContaining("ended after " + content.length + " bytes")
                    .hasMessageContaining("declared uncompressed size is " + declared);
        }
        assertThat(delivered.toByteArray()).isEqualTo(content);
    }

    /** The compressed size bounds what is read from the archive, so a short one starves the inflater. */
    @Test
    public void testDeflatedEntryWithTruncatedCompressedDataIsRejected() throws IOException {
        byte[] content = randomBytes(10_000, 2);
        byte[] archive = zipOf(Zip64Mode.Never, deflated("entry", content), stored("after", compressibleBytes(5_000)));
        archive = withDeclaredCompressedSize(archive, "entry", compressedSizeOf(archive, "entry") / 2);
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        var delivered = new ByteArrayOutputStream();
        try (var data = entryNamed(reader, "entry").getData()) {
            assertThatThrownBy(() -> data.transferTo(delivered))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[entry]");
        }
        assertThat(delivered.toByteArray()).isEqualTo(Arrays.copyOf(content, delivered.size()));
        assertThat(delivered.size()).isLessThan(content.length);
    }

    /** A first byte of 0xFF opens a deflate block of the reserved type 3, which no inflater accepts. */
    @Test
    public void testCorruptDeflateDataIsRejected() throws IOException {
        byte[] archive = zipOf(Zip64Mode.Never, deflated("entry", compressibleBytes(1_000)));
        archive[(int) dataOffsetOf(archive, "entry")] = (byte) 0xFF;
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));

        try (var data = entryNamed(reader, "entry").getData()) {
            assertThatThrownBy(() -> data.transferTo(new ByteArrayOutputStream()))
                    .isInstanceOf(InvalidZipException.class)
                    .hasMessageContaining("[entry]")
                    .hasCauseInstanceOf(DataFormatException.class);
        }
    }

    /**
     * A zip64 size is a 64-bit field, so one at or above 2^63 arrives negative once read as a
     * signed long. The central directory parse refuses either size of a deflated entry as invalid,
     * so it never reaches the inflater's arithmetic. The uncompressed size is also covered for
     * stored entries by {@link #testZip64EntrySizeThatReadsAsNegativeIsRejected()}; the compressed
     * size only matters once an entry is deflated.
     *
     * @param field 0 for the uncompressed size, 8 for the compressed size: their order within
     *              the zip64 extra field
     */
    @ParameterizedTest
    @ValueSource(ints = { 0, 8 })
    public void testDeflatedEntryWithAnOutOfRangeZip64SizeIsRejected(int field) throws IOException {
        byte[] archive = zipOf(Zip64Mode.Always, deflated("entry", compressibleBytes(1_000)));
        ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(zip64SizesInCentralDirectoryOf(archive, "entry") + field, Long.MIN_VALUE);
        var channel = new SeekableInMemoryByteChannel(archive);

        assertThatThrownBy(() -> new ZipReader(channel))
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("[entry]")
                .hasMessageContaining(field == 0 ? "claims a size of " : "claims a compressed size of ")
                .hasMessageContaining(Long.toUnsignedString(Long.MIN_VALUE))
                .hasMessageContaining("which no archive can hold");
    }

    @Test
    public void testReadingAClosedDeflatedStreamFails() throws IOException {
        var reader = new ZipReader(new SeekableInMemoryByteChannel(
                zipOf(Zip64Mode.Never, deflated("entry", compressibleBytes(1_000)))));
        var data = entryNamed(reader, "entry").getData();
        data.close();
        data.close();

        assertThatThrownBy(() -> data.read(new byte[10])).isInstanceOf(IOException.class);
    }

    private static boolean copyOnce(InputStream in, byte[] buf, ByteArrayOutputStream out) throws IOException {
        int n = in.read(buf, 0, buf.length);
        if (n == -1) {
            return true;
        }
        out.write(buf, 0, n);
        return false;
    }

    /** Text that deflate shrinks a great deal, so a deflated fixture is visibly compressed. */
    static byte[] compressibleBytes(int size) {
        byte[] pattern = "the quick brown fox jumps over the lazy dog. ".getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[size];
        for (int i = 0; i < size; i++) {
            out[i] = pattern[i % pattern.length];
        }
        return out;
    }

    /** Incompressible bytes, so the deflate stream is about as long as its output. */
    private static byte[] randomBytes(int size, long seed) {
        byte[] out = new byte[size];
        new Random(seed).nextBytes(out);
        return out;
    }

    private static ZipReader.Entry entryNamed(ZipReader reader, String name) {
        return reader.getEntries().stream()
                .filter(e -> e.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no entry named " + name));
    }

    private static byte[] readEntryBytes(ZipReader reader, String name) throws IOException {
        var data = new ByteArrayOutputStream();
        try (var in = entryNamed(reader, name).getData()) {
            in.transferTo(data);
        }
        return data.toByteArray();
    }

    static final class Item {
        final String name;
        final int method;
        final byte[] content;

        private Item(String name, int method, byte[] content) {
            this.name = name;
            this.method = method;
            this.content = content;
        }
    }

    static Item stored(String name, byte[] content) {
        return new Item(name, ZipEntry.STORED, content);
    }

    static Item deflated(String name, byte[] content) {
        return new Item(name, ZipEntry.DEFLATED, content);
    }

    /**
     * Builds an archive with commons-compress, an implementation independent of the one under
     * test. It writes to a seekable channel, so every size lands in the local header as well as
     * the central directory.
     */
    static byte[] zipOf(Zip64Mode zip64Mode, Item... items) throws IOException {
        var channel = new SeekableInMemoryByteChannel();
        try (var zip = new ZipArchiveOutputStream(channel)) {
            zip.setUseZip64(zip64Mode);
            for (var item : items) {
                var entry = new ZipArchiveEntry(item.name);
                entry.setMethod(item.method);
                zip.putArchiveEntry(entry);
                zip.write(item.content);
                zip.closeArchiveEntry();
            }
            zip.finish();
            return Arrays.copyOf(channel.array(), (int) channel.size());
        }
    }

    private static final int CENTRAL_FILE_HEADER_SIGNATURE = 0x02014b50;
    private static final int LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
    /** Field offsets within a central directory file header (APPNOTE 4.3.12). */
    private static final int CDH_METHOD = 10;
    private static final int CDH_COMPRESSED_SIZE = 20;
    private static final int CDH_UNCOMPRESSED_SIZE = 24;
    private static final int CDH_NAME_LENGTH = 28;
    private static final int CDH_EXTRA_LENGTH = 30;
    private static final int CDH_COMMENT_LENGTH = 32;
    private static final int CDH_LOCAL_HEADER_OFFSET = 42;
    private static final int CDH_FIXED_SIZE = 46;
    private static final int ZIP64_EXTRA_ID = 0x0001;
    private static final long ZIP64_SIZE_SENTINEL = 0xFFFFFFFFL;
    /** Field offsets within a local file header (APPNOTE 4.3.7). */
    private static final int LFH_METHOD = 8;
    private static final int LFH_COMPRESSED_SIZE = 18;
    private static final int LFH_NAME_LENGTH = 26;
    private static final int LFH_EXTRA_LENGTH = 28;
    private static final int LFH_FIXED_SIZE = 30;

    /**
     * Finds the central directory file header for {@code name}. Walks the central directory from
     * the end of central directory record, so it handles only archives that are not zip64 and
     * carry no comment -- which is every archive these patching helpers are used on.
     */
    private static int centralDirectoryHeaderOf(byte[] archive, String name) {
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        int eocd = archive.length - EOCD_SIZE;
        assertThat(buf.getInt(eocd)).isEqualTo(EOCD_SIGNATURE);
        int entries = buf.getShort(eocd + 10) & 0xFFFF;
        int header = buf.getInt(eocd + 16);
        for (int i = 0; i < entries; i++) {
            assertThat(buf.getInt(header)).isEqualTo(CENTRAL_FILE_HEADER_SIGNATURE);
            int nameLength = buf.getShort(header + CDH_NAME_LENGTH) & 0xFFFF;
            if (new String(archive, header + CDH_FIXED_SIZE, nameLength, StandardCharsets.UTF_8).equals(name)) {
                return header;
            }
            header += CDH_FIXED_SIZE + nameLength
                    + (buf.getShort(header + CDH_EXTRA_LENGTH) & 0xFFFF)
                    + (buf.getShort(header + CDH_COMMENT_LENGTH) & 0xFFFF);
        }
        throw new AssertionError("no central directory entry named " + name);
    }

    /**
     * Finds the sizes in the zip64 extra field of {@code name}'s central directory header: the
     * uncompressed size, then the compressed size. Scans for the header rather than walking from
     * the end of central directory record, so it works on a zip64 archive.
     */
    private static int zip64SizesInCentralDirectoryOf(byte[] archive, String name) {
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        for (int header = 0; header + CDH_FIXED_SIZE + nameBytes.length <= archive.length; header++) {
            if (buf.getInt(header) != CENTRAL_FILE_HEADER_SIGNATURE
                    || (buf.getShort(header + CDH_NAME_LENGTH) & 0xFFFF) != nameBytes.length
                    || !Arrays.equals(archive, header + CDH_FIXED_SIZE, header + CDH_FIXED_SIZE + nameBytes.length,
                            nameBytes, 0, nameBytes.length)) {
                continue;
            }
            assertThat(buf.getInt(header + CDH_UNCOMPRESSED_SIZE)).isEqualTo((int) ZIP64_SIZE_SENTINEL);
            assertThat(buf.getInt(header + CDH_COMPRESSED_SIZE)).isEqualTo((int) ZIP64_SIZE_SENTINEL);
            int field = header + CDH_FIXED_SIZE + nameBytes.length;
            int end = field + (buf.getShort(header + CDH_EXTRA_LENGTH) & 0xFFFF);
            while (field < end) {
                if ((buf.getShort(field) & 0xFFFF) == ZIP64_EXTRA_ID) {
                    return field + 4;
                }
                field += 4 + (buf.getShort(field + 2) & 0xFFFF);
            }
            throw new AssertionError("no zip64 extra field for " + name);
        }
        throw new AssertionError("no central directory entry named " + name);
    }

    static int compressionMethodOf(byte[] archive, String name) {
        return ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN)
                .getShort(centralDirectoryHeaderOf(archive, name) + CDH_METHOD) & 0xFFFF;
    }

    private static long compressedSizeOf(byte[] archive, String name) {
        return ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN)
                .getInt(centralDirectoryHeaderOf(archive, name) + CDH_COMPRESSED_SIZE) & 0xFFFFFFFFL;
    }

    private static long localHeaderOffsetOf(byte[] archive, String name) {
        return ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN)
                .getInt(centralDirectoryHeaderOf(archive, name) + CDH_LOCAL_HEADER_OFFSET) & 0xFFFFFFFFL;
    }

    private static long dataOffsetOf(byte[] archive, String name) {
        var buf = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
        int localHeader = (int) localHeaderOffsetOf(archive, name);
        assertThat(buf.getInt(localHeader)).isEqualTo(LOCAL_FILE_HEADER_SIGNATURE);
        return localHeader + LFH_FIXED_SIZE
                + (buf.getShort(localHeader + LFH_NAME_LENGTH) & 0xFFFF)
                + (buf.getShort(localHeader + LFH_EXTRA_LENGTH) & 0xFFFF);
    }

    /**
     * Rewrites an entry's compression method in its local header as well as the central
     * directory, so the two agree as they would in an archive written that way.
     */
    static byte[] withCompressionMethod(byte[] archive, String name, int method) {
        byte[] patched = archive.clone();
        var buf = ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort(centralDirectoryHeaderOf(patched, name) + CDH_METHOD, (short) method);
        buf.putShort((int) localHeaderOffsetOf(patched, name) + LFH_METHOD, (short) method);
        return patched;
    }

    /** Rewrites the uncompressed size in the central directory, which is the one the reader trusts. */
    static byte[] withDeclaredUncompressedSize(byte[] archive, String name, long size) {
        byte[] patched = archive.clone();
        ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(centralDirectoryHeaderOf(patched, name) + CDH_UNCOMPRESSED_SIZE, (int) size);
        return patched;
    }

    /** Rewrites the compressed size in the central directory, which is the one the reader trusts. */
    private static byte[] withDeclaredCompressedSize(byte[] archive, String name, long size) {
        byte[] patched = archive.clone();
        ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(centralDirectoryHeaderOf(patched, name) + CDH_COMPRESSED_SIZE, (int) size);
        return patched;
    }
}
