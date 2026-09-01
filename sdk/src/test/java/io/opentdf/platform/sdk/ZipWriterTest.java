package io.opentdf.platform.sdk;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipExtraField;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.archivers.zip.ZipShort;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.Random;
import java.util.zip.CRC32;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class ZipWriterTest {
    @Test
    public void writesMultipleFilesToArchive() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out);
        writer.data("file1∞®ƒ両†.txt", "Hello world!".getBytes(StandardCharsets.UTF_8));
        writer.data("file2.txt", "Here are some more things to look at".getBytes(StandardCharsets.UTF_8));

        try (var entry = writer.stream("the streaming one")) {
            new ByteArrayInputStream("this is a long long stream".getBytes(StandardCharsets.UTF_8))
                    .transferTo(entry);
        }
        writer.finish();

        SeekableByteChannel chan = new SeekableInMemoryByteChannel(out.toByteArray());
        ZipFile z = new ZipFile.Builder().setSeekableByteChannel(chan).get();
        var entry1 = z.getEntry("file1∞®ƒ両†.txt");
        assertThat(entry1).isNotNull();
        var entry1Data = getDataStream(z, entry1);
        assertThat(entry1Data.toString(StandardCharsets.UTF_8)).isEqualTo("Hello world!");

        var entry2 = z.getEntry("file2.txt");
        assertThat(entry1).isNotNull();
        assertThat(getDataStream(z, entry2).toString(StandardCharsets.UTF_8)).isEqualTo("Here are some more things to look at");

        var entry3 = z.getEntry("the streaming one");
        assertThat(entry3).isNotNull();
        assertThat(getDataStream(z, entry3).toString(StandardCharsets.UTF_8)).isEqualTo("this is a long long stream");
    }
    @Test
    public void createsNonZip64Archive() throws IOException {
        // when we create things using only byte arrays we create an archive that is non zip64
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out);
        writer.data("file1∞®ƒ両†.txt", "Hello world!".getBytes(StandardCharsets.UTF_8));
        writer.data("file2.txt", "Here are some more things to look at".getBytes(StandardCharsets.UTF_8));
        writer.finish();

        SeekableByteChannel chan = new SeekableInMemoryByteChannel(out.toByteArray());
        ZipFile z = new ZipFile.Builder().setSeekableByteChannel(chan).get();
        var entry1 = z.getEntry("file1∞®ƒ両†.txt");
        assertThat(entry1).isNotNull();
        var entry1Data = getDataStream(z, entry1);
        assertThat(entry1Data.toString(StandardCharsets.UTF_8)).isEqualTo("Hello world!");

        var entry2 = z.getEntry("file2.txt");
        assertThat(entry1).isNotNull();
        assertThat(getDataStream(z, entry2).toString(StandardCharsets.UTF_8)).isEqualTo("Here are some more things to look at");

        assertThat(containsZip64EndOfCentralDirectory(out.toByteArray()))
                .withFailMessage("expected a small byte-array-only archive to stay non-zip64")
                .isFalse();
    }

    /**
     * The manifest is written after the payload, so in a large TDF its local header offset is
     * past the 32-bit central directory field. Uses the lowered threshold so the real zip64 path
     * runs against an archive small enough to check here.
     */
    @Test
    public void writesReadableZip64EntriesForOffsetsPastTheThreshold() throws IOException {
        var manifest = "{\"payload\":{\"protocol\":\"zip\"}}";
        var payload = "a payload long enough to push the manifest past the threshold";

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        var writer = new ZipWriter(out, 8);
        writer.data("small.txt", "tiny".getBytes(StandardCharsets.UTF_8));
        try (var entry = writer.stream("0.payload")) {
            new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)).transferTo(entry);
        }
        writer.data("0.manifest.json", manifest.getBytes(StandardCharsets.UTF_8));
        writer.finish();

        var archive = out.toByteArray();
        assertThat(containsZip64EndOfCentralDirectory(archive))
                .withFailMessage("expected the lowered threshold to produce a zip64 archive")
                .isTrue();

        // our own reader
        try (var chan = new SeekableInMemoryByteChannel(archive)) {
            var reader = new ZipReader(chan);
            assertThat(reader.getEntries().size()).isEqualTo(3);
            assertThat(readEntry(reader, "small.txt")).isEqualTo("tiny");
            assertThat(readEntry(reader, "0.payload")).isEqualTo(payload);
            assertThat(readEntry(reader, "0.manifest.json")).isEqualTo(manifest);
        }

        // and an independent implementation, so we aren't just agreeing with ourselves
        try (var chan = new SeekableInMemoryByteChannel(archive)) {
            ZipFile z = new ZipFile.Builder().setSeekableByteChannel(chan).get();
            assertThat(getDataStream(z, z.getEntry("small.txt")).toString(StandardCharsets.UTF_8))
                    .isEqualTo("tiny");
            assertThat(getDataStream(z, z.getEntry("0.payload")).toString(StandardCharsets.UTF_8))
                    .isEqualTo(payload);
            assertThat(getDataStream(z, z.getEntry("0.manifest.json")).toString(StandardCharsets.UTF_8))
                    .isEqualTo(manifest);

            // the manifest sits past the threshold, so it has to carry a zip64 extra field
            // rather than a truncated 32-bit offset. without this the test would still pass
            // against a writer that never marks byte array entries as zip64
            assertThat(zip64ExtraField(z, "0.manifest.json"))
                    .withFailMessage("the entry past the threshold was not written as zip64")
                    .isNotNull();
            // and an entry below the threshold is left alone
            assertThat(zip64ExtraField(z, "small.txt"))
                    .withFailMessage("an entry below the threshold should not be zip64")
                    .isNull();
        }
    }

    @Test
    public void refusesToTruncateAnOffsetIntoThirtyTwoBits() {
        assertThatThrownBy(() -> ZipWriter.checkFitsInCentralDirectory("0.manifest.json", 1L << 31, 10))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("0.manifest.json");

        assertThatThrownBy(() -> ZipWriter.checkFitsInCentralDirectory("big.bin", 0, 1L << 32))
                .isInstanceOf(SDKException.class);

        assertThatCode(() -> ZipWriter.checkFitsInCentralDirectory(
                "boundary.bin", Integer.MAX_VALUE, Integer.MAX_VALUE))
                .doesNotThrowAnyException();
    }

    @Test
    public void rejectsAnOutOfRangeZip64Threshold() {
        var out = new ByteArrayOutputStream();
        assertThatThrownBy(() -> new ZipWriter(out, -1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ZipWriter(out, 1L << 32)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @Disabled("this takes a long time and shouldn't run on build machines")
    public void testWritingLargeFile() throws IOException {
        var trailingEntry = "{\"written\":\"after the big payload\"}";
        var random = new Random();
        // create a file between 7 and 8 GB
        long fileSize = 7 * (1L << 30) + (long)Math.floor(random.nextDouble() * (1L << 30));
        var testFile = File.createTempFile("big-file", "");
        testFile.deleteOnExit();
        try (var out = new FileOutputStream(testFile)) {
            var buf = new byte[2048];
            for (long i = 0; i < (fileSize / buf.length); i++) {
                random.nextBytes(buf);
                out.write(buf);
            }
            buf = new byte[(int)(fileSize % 2048)];
            random.nextBytes(buf);
            out.write(buf);
        }

        assertThat(testFile.length())
                .withFailMessage("didn't write a file of the expected size")
                .isEqualTo(fileSize);

        var zipFile = File.createTempFile("zip-file", "zip");
        zipFile.deleteOnExit();
        try (var in = new FileInputStream(testFile)) {
            try (var out = new FileOutputStream(zipFile)) {
                var writer = new ZipWriter(out);
                try (var entry = writer.stream("a big one")) {
                    in.transferTo(entry);
                }
                // a byte array entry after the big stream, the way a TDF appends its manifest.
                // its local header offset is past 32 bits, so it has to be written as zip64
                writer.data("0.manifest.json", trailingEntry.getBytes(StandardCharsets.UTF_8));
                writer.finish();
            }
        }

        try (var chan = FileChannel.open(zipFile.toPath(), StandardOpenOption.READ)) {
            var reader = new ZipReader(chan);
            assertThat(readEntry(reader, "0.manifest.json"))
                    .withFailMessage("couldn't read back an entry written past the 32-bit offset limit")
                    .isEqualTo(trailingEntry);
        }

        var unzippedData = File.createTempFile("big-file-unzipped", "");
        unzippedData.deleteOnExit();
        try (var unzippedStream = new FileOutputStream(unzippedData)) {
            try (var chan = FileChannel.open(zipFile.toPath(), StandardOpenOption.READ)) {
                ZipFile z = new ZipFile.Builder().setSeekableByteChannel(chan).get();
                var entry = z.getEntry("a big one");
                z.getInputStream(entry).transferTo(unzippedStream);
            }
        }

        assertThat(unzippedData.length())
                .withFailMessage("extracted file was of the wrong length")
                .isEqualTo(testFile.length());


        var unzippedCRC = crcOfWholeFile(unzippedData);
        unzippedData.delete();

        var testFileCRC = crcOfWholeFile(testFile);

        assertThat(unzippedCRC)
                .withFailMessage("the extracted file's CRC differs from the CRC of the test data")
                .isEqualTo(testFileCRC);

        var ourUnzippedData = File.createTempFile("big-file-we-unzipped", "");
        ourUnzippedData.deleteOnExit();
        try (var unzippedStream = new FileOutputStream(ourUnzippedData)) {
            try (var chan = FileChannel.open(zipFile.toPath(), StandardOpenOption.READ)) {
                ZipReader reader = new ZipReader(chan);
                assertThat(reader.getEntries().size()).isEqualTo(2);
                var bigEntry = reader.getEntries().stream()
                        .filter(e -> e.getName().equals("a big one"))
                        .findFirst()
                        .orElseThrow();
                bigEntry.getData().transferTo(unzippedStream);
            }
        }
        testFile.delete();

        assertThat(crcOfWholeFile(ourUnzippedData))
                .withFailMessage("the file we extracted differs from the CRC of the test data")
                .isEqualTo(testFileCRC);
    }

    @Nonnull
    private static ByteArrayOutputStream getDataStream(ZipFile z, ZipArchiveEntry entry) throws IOException {
        var entry1Data = new ByteArrayOutputStream();
        z.getInputStream(entry).transferTo(entry1Data);
        return entry1Data;
    }

    /** commons-compress keeps {@code Zip64ExtendedInformationExtraField.HEADER_ID} package-private. */
    private static final ZipShort ZIP64_HEADER_ID = new ZipShort(0x0001);

    private static ZipExtraField zip64ExtraField(ZipFile z, String name) {
        return z.getEntry(name).getExtraField(ZIP64_HEADER_ID);
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

    /** Looks for the zip64 end of central directory signature, 0x06064b50 little-endian. */
    private static boolean containsZip64EndOfCentralDirectory(byte[] archive) {
        for (int i = 0; i + 4 <= archive.length; i++) {
            if (archive[i] == 0x50 && archive[i + 1] == 0x4b
                    && archive[i + 2] == 0x06 && archive[i + 3] == 0x06) {
                return true;
            }
        }
        return false;
    }

    private static long crcOfWholeFile(File file) throws IOException {
        var crc = new CRC32();
        var buf = new byte[1 << 16];
        try (var inputStream = new FileInputStream(file)) {
            int read;
            while ((read = inputStream.read(buf)) > 0) {
                crc.update(buf, 0, read);
            }
        }
        return crc.getValue();
    }
}
