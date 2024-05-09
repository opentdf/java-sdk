package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class ZipReader {

    public static final int END_OF_CENTRAL_DIRECTORY_SIZE = 22;
    public static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE = 20;
    public static final int ZIP64_END_OF_CENTRAL_DIRECTORY_SIZE = 56;
    private static final int LOCAL_FILE_HEADER_SIZE = 30;

    public class Entry {
        private final String name;
        private final long offset;

        private final long size;

        public Entry(String name, long offset, long size) {
            this.name = name;
            this.offset = offset;
            this.size = size;
        }

        public OutputStream getData() {
            return new OutputStream() {
                @Override
                public void write(int b) {

                }
            };
        }
    }

    private static class CentralDirectoryRecord {
        final int numEntries;
        final long offsetToStart;

        public CentralDirectoryRecord(int numEntries, long offsetToStart) {
            this.numEntries = numEntries;
            this.offsetToStart = offsetToStart;
        }
    }

    private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
    private static final int ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06064b50;
    private static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE = 0x07064b50;
    private static final int CENTRAL_DIRECTORY_LOCATOR_SIGNATURE  =  0x02014b50;
    private static final int LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
    private static final int ZIP64_MAGICVAL = 0xFFFFFFFF;
    private static final int ZIP64_EXTID= 0x0001;

    CentralDirectoryRecord readEndOfCentralDirectory(ByteBuffer buffer) {
        long fileSize = buffer.limit();
        long pointer = fileSize - 22; // 22 is the minimum size of the EOCDR

        // Search for the EOCDR from the end of the file
        while (pointer >= 0) {
            buffer.position((int)pointer);
            int signature = buffer.getInt();
            if (signature == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
                System.out.println("Found End of Central Directory Record");
                break;
            }
            pointer--;
        }

        if (pointer < 0) {
            throw new RuntimeException("Invalid tdf file");
        }

        // Read the EOCDR
        short _diskNumber = buffer.getShort();
        short _centralDirectoryDiskNumber = buffer.getShort();
        short _numEntriesThisDisk = buffer.getShort();
        short numEntries = buffer.getShort();
        int _centralDirectorySize = buffer.getInt();
        long centralDirectoryStart = buffer.getInt();
        short _commentLength = buffer.getShort();

        // buffer's position at the start of the Central Directory
        if (centralDirectoryStart == ZIP64_MAGICVAL) {
            long zip64CentralDirectoryStart = fileSize - (ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE + END_OF_CENTRAL_DIRECTORY_SIZE);
            buffer.position((int)zip64CentralDirectoryStart);
            int signature = buffer.getInt() ;
            if (signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
                throw new RuntimeException("Invalid Zip64 End of Central Directory Record Signature");
            }
            long zip64EndOfCentralDirectoryStart = fileSize -
                    (ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE + END_OF_CENTRAL_DIRECTORY_SIZE + ZIP64_END_OF_CENTRAL_DIRECTORY_SIZE);
            buffer.position((int)zip64EndOfCentralDirectoryStart);
            return readZip64EndOfCentralDirectoryRecord(buffer);
        }

        return new CentralDirectoryRecord(numEntries, centralDirectoryStart);
    }

    private CentralDirectoryRecord readZip64EndOfCentralDirectoryRecord(ByteBuffer buffer) {
        int signature = buffer.getInt() ;
        if (signature != ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
            throw new RuntimeException("Invalid Zip64 End of Central Directory Record ");
        }
        long sizeOfZip64EndOfCentralDirectoryRecord = buffer.getLong();
        short versionMadeBy = buffer.getShort();
        short versionNeededToExtract = buffer.getShort();
        int diskNumber = buffer.getInt();
        int diskWithCentralDirectory = buffer.getInt();
        long numEntriesOnThisDisk = buffer.getLong();
        int numEntries = (int)buffer.getLong();
        long centralDirectorySize = buffer.getLong();
        long offsetToStartOfCentralDirectory = buffer.getLong();

        return new CentralDirectoryRecord(numEntries, offsetToStartOfCentralDirectory);
    }

    public int getNumEntries() {
        return numEntries;
    }

    private static class LocalFileInfo {
        byte[] fileName;
        byte[] extraField;
        final long offsetToLocalHeader;

        LocalFileInfo(byte[] fileName, byte[] extraField, long offsetToLocalHeader) {
            this.fileName = fileName;
            this.extraField = extraField;
            this.offsetToLocalHeader = offsetToLocalHeader;
        }
    }
    public LocalFileInfo readCentralDirectoryFileHeader(ByteBuffer buffer) {
        int signature = buffer.getInt();
        if (signature != CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new RuntimeException("Invalid Central Directory File Header Signature");
        }
        short versionMadeBy = buffer.getShort();
        short versionNeededToExtract = buffer.getShort();
        short generalPurposeBitFlag = buffer.getShort();
        short compressionMethod = buffer.getShort();
        short lastModFileTime = buffer.getShort();
        short lastModFileDate = buffer.getShort();
        int crc32 = buffer.getInt();
        int compressedSize = buffer.getInt();
        int uncompressedSize = buffer.getInt();
        int fileNameLength = buffer.getShort();
        int extraFieldLength = buffer.getShort();
        short fileCommentLength = buffer.getShort();
        short diskNumberStart = buffer.getShort();
        short internalFileAttributes = buffer.getShort();
        int externalFileAttributes = buffer.getInt();
        long relativeOffsetOfLocalHeader = buffer.getInt() ;

        byte[] fileName = new byte[fileNameLength];
        buffer.get(fileName);
        String fileNameString = new String(fileName, StandardCharsets.UTF_8);

        if (compressedSize == ZIP64_MAGICVAL || uncompressedSize == ZIP64_MAGICVAL || relativeOffsetOfLocalHeader == ZIP64_MAGICVAL) {
            // Parse the extra field
            for (int i = 0; i < extraFieldLength; ) {
                int headerId = buffer.getShort();
                int dataSize = buffer.getShort();
                i += 4;

                if (headerId == ZIP64_EXTID) {
                    if (compressedSize == ZIP64_MAGICVAL) {
                        compressedSize = (int)buffer.getLong();
                        i += 8;
                    }
                    if (uncompressedSize == ZIP64_MAGICVAL) {
                        uncompressedSize = (int)buffer.getLong();
                        i += 8;
                    }
                    if (relativeOffsetOfLocalHeader == ZIP64_MAGICVAL) {
                        relativeOffsetOfLocalHeader = buffer.getLong();
                        i += 8;
                    }
                } else {
                    // Skip other extra fields
                    buffer.position(buffer.position() + dataSize);
                    i += dataSize;
                }
            }
        }

        byte[] extraField = new byte[extraFieldLength];
        buffer.get(extraField);

//        byte[] fileComment = new byte[fileCommentLength];
//        buffer.get(fileComment);

        return new LocalFileInfo(fileName, extraField, relativeOffsetOfLocalHeader);
    }

    private static class LocalFileValues {
        final private byte[] name;
        final private byte[] extraField;
        private final int compressedSize;
        private final int uncompressedSize;

        private LocalFileValues(byte[] name, byte[] extraField, int compressedSize, int uncompressedSize) {
            this.name = name;
            this.extraField = extraField;
            this.compressedSize = compressedSize;
            this.uncompressedSize = uncompressedSize;
        }
    }

    LocalFileValues readLocalFileHeader(ByteBuffer buffer) {
        int signature = buffer.getInt();
        if (signature != LOCAL_FILE_HEADER_SIGNATURE) {
            throw new RuntimeException("Invalid Local File Header Signature");
        }
        short versionNeededToExtract = buffer.getShort();
        short generalPurposeBitFlag = buffer.getShort();
        short compressionMethod = buffer.getShort();
        short lastModFileTime = buffer.getShort();
        short lastModFileDate = buffer.getShort();
        int crc32 = buffer.getInt();
        int compressedSize = buffer.getInt();
        int uncompressedSize = buffer.getInt();
        short fileNameLength = buffer.getShort();
        short extraFieldLength = buffer.getShort();

        byte[] fileName = new byte[fileNameLength];
        buffer.get(fileName);

        byte[] extraField = new byte[extraFieldLength];
        buffer.get(extraField);

        return new LocalFileValues(fileName, extraField, compressedSize, uncompressedSize);

        /*byte[] fileData = new byte[compressedSize];
        buffer.get(fileData);

       if (compressionMethod == 0) {
            String fileContent = new String(fileData, StandardCharsets.UTF_8);
            System.out.println("File content: " + fileContent);
        } else {
            System.out.println("File is compressed, need to decompress it first");
        }*/
    }

    final int BUFFER_CAPACITY = 1024 * 4; // A central directory bigger than this seems excessive

    public ZipReader(SeekableByteChannel channel) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(BUFFER_CAPACITY);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        long offset = Math.max(0, channel.size() - BUFFER_CAPACITY);
        channel.position(offset);
        while (channel.read(buf) > 0);
        buf.flip();

        var centralDirectory = readEndOfCentralDirectory(buf);

        numEntries = centralDirectory.numEntries;
        centralDirectoryStart = centralDirectory.offsetToStart;
        zipChannel = channel;
    }
    
    final SeekableByteChannel zipChannel;

    private class ZipEntryIterator implements Iterator<Entry> {
        int currentItem;
        long currentCentralDirectoryOffset;
        final int numItems;
        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_CAPACITY);

        ZipEntryIterator(int numItems, long centralDirectoryStart) {
            this.numItems = numItems;
            this.currentItem = 0;
            this.currentCentralDirectoryOffset = centralDirectoryStart;
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }

        @Override
        public boolean hasNext() {
            return currentItem < numItems;
        }

        @Override
        public Entry next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            try {
                return readNextFile();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private Entry readNextFile() throws IOException {
            buffer.clear();

            zipChannel.position(currentCentralDirectoryOffset);
            zipChannel.read(buffer);
            buffer.flip();
            var localFileInfo = readCentralDirectoryFileHeader(buffer);
            buffer.clear();

            zipChannel.position(localFileInfo.offsetToLocalHeader);
            zipChannel.read(buffer);
            buffer.flip();

            var fileValues = readLocalFileHeader(buffer);
            currentItem += 1;
            currentCentralDirectoryOffset += 46 + fileValues.name.length + fileValues.extraField.length;

            return new Entry(
                    new String(fileValues.name, StandardCharsets.UTF_8),
                    localFileInfo.offsetToLocalHeader + LOCAL_FILE_HEADER_SIZE,
                    fileValues.compressedSize
            );
        }
    }



    public Iterator<Entry> getEntries() {
        return new ZipEntryIterator(numEntries, centralDirectoryStart);
    }
    final int numEntries;
    final long centralDirectoryStart;
}