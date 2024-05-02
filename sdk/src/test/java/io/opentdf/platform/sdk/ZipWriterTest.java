package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

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