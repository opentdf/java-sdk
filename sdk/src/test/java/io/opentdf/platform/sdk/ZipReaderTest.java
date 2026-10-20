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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.DataFormatException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
            var reader = new ZipReader(channel);
            assertThat(reader.getEntries()).hasSize(3);
            assertThat(readEntry(reader, "small.txt")).isEqualTo("tiny");
            assertThat(readEntry(reader, "0.payload")).isEqualTo(PAYLOAD);
            assertThat(readEntry(reader, "0.manifest.json")).isEqualTo(MANIFEST);
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

    private static String readEntry(ZipReader reader, String name) throws IOException {
        var entry = reader.getEntries().stream()
                .filter(e -> e.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no entry named " + name));
        var data = new ByteArrayOutputStream();
        entry.getData().transferTo(data);
        return data.toString(StandardCharsets.UTF_8);
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
     * signed long. A deflated entry declaring one is refused as invalid, not left to fail on the
     * arithmetic with an exception callers don't expect from a bad archive.
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
        var reader = new ZipReader(new SeekableInMemoryByteChannel(archive));
        var entry = entryNamed(reader, "entry");

        assertThatThrownBy(entry::getData)
                .isInstanceOf(InvalidZipException.class)
                .hasMessageContaining("[entry]")
                .hasMessageContaining("out of range");
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
    private static byte[] withDeclaredUncompressedSize(byte[] archive, String name, long size) {
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
