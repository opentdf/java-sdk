package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.OpenOption;
import java.nio.file.StandardOpenOption;
import java.util.Set;

public class ZipWriterTest {
    @Test
    public void writesMultipleFilesToArchive() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ZipWriter archiveWriter = new ZipWriter(outputStream);

        String filename1 = "file1.txt";
        String content1 = "Hello, world!";
        archiveWriter.addHeader(filename1, content1.getBytes(StandardCharsets.UTF_8).length);
        archiveWriter.addData(content1.getBytes(StandardCharsets.UTF_8));
        archiveWriter.finish();

        String filename2 = "file2.txt";
        String content2 = "This is another file.";
        archiveWriter.addHeader(filename2, content2.getBytes(StandardCharsets.UTF_8).length);
        archiveWriter.addData(content2.getBytes(StandardCharsets.UTF_8));
        archiveWriter.finish();

        byte[] zipData = outputStream.toByteArray();
        assertTrue(zipData.length > 0);
    }

    @Test
    public void zipFileRoundTrips() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ZipWriter archiveWriter = new ZipWriter(outputStream);

        String filename1 = "file1.txt";
        String content1 = "Hello, world!";
        archiveWriter.addHeader(filename1, content1.getBytes(StandardCharsets.UTF_8).length);
        archiveWriter.addData(content1.getBytes(StandardCharsets.UTF_8));
        archiveWriter.finish();

        String filename2 = "file2.txt";
        String content2 = "This is another file.";
        archiveWriter.addHeader(filename2, content2.getBytes(StandardCharsets.UTF_8).length);
        archiveWriter.addData(content2.getBytes(StandardCharsets.UTF_8));
        archiveWriter.finish();

        byte[] zipData = outputStream.toByteArray();
        assertTrue(zipData.length > 0);

        var tmpFile = File.createTempFile("zipwriter-tests", "");
        tmpFile.deleteOnExit();

        try (var channel = FileChannel.open(tmpFile.toPath(), Set.of(StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.READ))) {
            MappedByteBuffer mapped = channel.map(FileChannel.MapMode.READ_WRITE, 0, zipData.length);
            mapped.put(zipData, 0, zipData.length);

            var zipReader = new ZipReader(channel);
            assertEquals(zipReader.numEntries, 2);

            for (var entries = zipReader.getEntries(); entries.hasNext(); ) {
                var entry = entries.next();
            }
        }
    }

    @Test
    public void throwsExceptionForEmptyFilename() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ZipWriter archiveWriter = new ZipWriter(outputStream);

        String filename = "";
        String content = "Hello, world!";

        assertThrows(IllegalArgumentException.class, () -> {
            archiveWriter.addHeader(filename, content.getBytes(StandardCharsets.UTF_8).length);
        });
    }
}