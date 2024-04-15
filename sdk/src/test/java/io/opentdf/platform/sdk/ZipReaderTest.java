package io.opentdf.platform.sdk;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ZipReaderTest {
    private ZipReader zipReader;
    private ByteBuffer buffer;
    private RandomAccessFile raf;
    private FileChannel fileChannel;


    @Test
    public void testZipReader() throws Exception {
        RandomAccessFile raf = new RandomAccessFile("src/test/resources/sample.txt.tdf", "r");
        FileChannel fileChannel = raf.getChannel();
        int bufferSize = 1024;
        long fileSize = fileChannel.size();
        long position = fileSize - bufferSize;
        if (position < 0) {
            position = fileSize;
        }

        ByteBuffer buffer = ByteBuffer.allocate((int)bufferSize);
        fileChannel.position(position);
        fileChannel.read(buffer);
        buffer.flip();

        ZipReader zipReader = new ZipReader();
        zipReader.readEndOfCentralDirectory(buffer);
        buffer.clear();
        long centralDirectoryOffset = zipReader.getCDOffset();
        int numEntries = zipReader.getNumEntries();
        for (int i = 0; i < numEntries; i++) {
            fileChannel.position(centralDirectoryOffset);
            fileChannel.read(buffer);
            buffer.flip();
            long offset = zipReader.readCentralDirectoryFileHeader(buffer);
            buffer.clear();
            fileChannel.position(offset);
            fileChannel.read(buffer);
            buffer.flip();
            zipReader.readLocalFileHeader(buffer);
            centralDirectoryOffset += 46 + zipReader.getFileNameLength()  + zipReader.getExtraFieldLength();
            buffer.clear();
        }

        assertEquals(2, zipReader.getNumEntries());
        assertNotNull(zipReader.getFileNameLength());
        assertNotNull(zipReader.getCDOffset());

        raf.close();
    }
}