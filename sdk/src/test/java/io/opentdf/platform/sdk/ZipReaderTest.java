package io.opentdf.platform.sdk;
import com.google.gson.Gson;
import org.apache.commons.compress.archivers.zip.Zip64Mode;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntryRequest;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ZipReaderTest {

    @Test
    public void testReadingExistingZip() throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile("src/test/resources/sample.txt.tdf", "r")) {
            var fileChannel = raf.getChannel();
            var zipReader = new ZipReader(fileChannel);
            var entries = zipReader.getEntries();
            assertThat(entries.size()).isEqualTo(2);
            for (var entry: entries) {
                var stream = new ByteArrayOutputStream();
                if (entry.getName().endsWith(".json")) {
                    entry.getData().transferTo(stream);
                    var data = stream.toString(StandardCharsets.UTF_8);
                    var map = new Gson().fromJson(data, Map.class);
                    assertThat(map.get("encryptionInformation")).isNotNull();
                }
            }
        }
    }

    @Test
    public void testRoundTripping32BitZipFiles() throws IOException {
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