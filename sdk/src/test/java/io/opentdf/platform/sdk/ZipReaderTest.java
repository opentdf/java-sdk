package io.opentdf.platform.sdk;
import org.junit.jupiter.api.Test;

import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ZipReaderTest {
    private ZipReader zipReader;
    private ByteBuffer buffer;
    private RandomAccessFile raf;
    private FileChannel fileChannel;


    @Test
    public void testReadingExistingZip() throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile("src/test/resources/sample.txt.tdf", "r")) {
            var fileChannel = raf.getChannel();
            var zipReader = new ZipReader(fileChannel);
            var entriesDetected = zipReader.getNumEntries();
            ArrayList<ZipReader.Entry> entriesExtracted = new ArrayList<>();
            for (var entries = zipReader.getEntries(); entries.hasNext(); ) {
                entriesExtracted.add(entries.next());
            }

            assertEquals(entriesDetected, entriesExtracted.size(), "wrong number of files in zip archive");
        }
    }

//        ZipReader zipReader = new ZipReader(fileChannel);
//        zipReader.readEndOfCentralDirectory(buffer);
//        buffer.clear();
//        long centralDirectoryOffset = zipReader.getCDOffset();
//        int numEntries = zipReader.getNumEntries();
//        for (int i = 0; i < numEntries; i++) {
//            fileChannel.position(centralDirectoryOffset);
//            fileChannel.read(buffer);
//            buffer.flip();
//            long offset = zipReader.readCentralDirectoryFileHeader(buffer);
//            buffer.clear();
//            fileChannel.position(offset);
//            fileChannel.read(buffer);
//            buffer.flip();
//            zipReader.readLocalFileHeader(buffer);
//            centralDirectoryOffset += 46 + zipReader.getFileNameLength()  + zipReader.getExtraFieldLength();
//            buffer.clear();
//        }
//
//        assertEquals(2, zipReader.getNumEntries());
//        assertNotNull(zipReader.getFileNameLength());
//        assertNotNull(zipReader.getCDOffset());
//
//        raf.close();
}