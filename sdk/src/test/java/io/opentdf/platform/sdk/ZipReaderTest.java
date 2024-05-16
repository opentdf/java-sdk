package io.opentdf.platform.sdk;
import com.google.gson.Gson;
import org.apache.commons.compress.archivers.zip.Zip64Mode;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
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

        ZipWriter writer = new ZipWriter();
        HashMap<String, byte[]> namesToData = new HashMap<>();
        for (var data: testData) {
            var fileName = (String)data[0];
            var content = (byte[])data[1];

            if (namesToData.containsKey(fileName)) {
                continue;
            }

            namesToData.put(fileName, content);

            if (r.nextBoolean()) {
                writer = writer.file(fileName, content);
            } else {
                writer = writer.file(fileName, new ByteArrayInputStream(content));
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writer.build(out);

        var channel = new SeekableInMemoryByteChannel(out.toByteArray());

        ZipReader reader = new ZipReader(channel);

        for (var entry: reader.getEntries()) {
            assertThat(namesToData).containsKey(entry.getName());
            var zipData = new ByteArrayOutputStream();
            entry.getData().transferTo(zipData);
            assertThat(zipData.toByteArray()).isEqualTo(namesToData.get(entry.getName()));
        }
    }
}