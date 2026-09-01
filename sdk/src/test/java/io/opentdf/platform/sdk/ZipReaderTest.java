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
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

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
            assertThat(reader.getEntries().size()).isEqualTo(3);
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
}