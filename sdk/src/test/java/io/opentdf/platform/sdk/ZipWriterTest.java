package io.opentdf.platform.sdk;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
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
    }

    @Test
    @Disabled("this takes a long time and shouldn't run on build machines")
    public void testWritingLargeFile() throws IOException {
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
                writer.finish();
            }
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


        var buf = new byte[2048];
        var unzippedCRC = new CRC32();
        try (var inputStream = new FileInputStream(unzippedData)) {
            var read = inputStream.read(buf);
            unzippedCRC.update(buf, 0, read);
        }
        unzippedData.delete();

        var testFileCRC = new CRC32();
        try (var inputStream = new FileInputStream(testFile)) {
            var read = inputStream.read(buf);
            testFileCRC.update(buf, 0, read);
        }
        testFile.delete();

        assertThat(unzippedCRC.getValue())
                .withFailMessage("the extracted file's CRC differs from the CRC of the test data")
                .isEqualTo(testFileCRC.getValue());

        var ourUnzippedData = File.createTempFile("big-file-we-unzipped", "");
        ourUnzippedData.deleteOnExit();
        try (var unzippedStream = new FileOutputStream(ourUnzippedData)) {
            try (var chan = FileChannel.open(zipFile.toPath(), StandardOpenOption.READ)) {
                ZipReader reader = new ZipReader(chan);
                assertThat(reader.getEntries().size()).isEqualTo(1);
                reader.getEntries().get(0).getData().transferTo(unzippedStream);
            }
        }

        var ourTestFileCRC = new CRC32();
        try (var inputStream = new FileInputStream(ourUnzippedData)) {
            var read = inputStream.read(buf);
            ourTestFileCRC.update(buf, 0, read);
        }

        assertThat(ourTestFileCRC.getValue())
                .withFailMessage("the file we extracted differs from the CRC of the test data")
                .isEqualTo(testFileCRC.getValue());
    }

    @Nonnull
    private static ByteArrayOutputStream getDataStream(ZipFile z, ZipArchiveEntry entry) throws IOException {
        var entry1Data = new ByteArrayOutputStream();
        z.getInputStream(entry).transferTo(entry1Data);
        return entry1Data;
    }
}
