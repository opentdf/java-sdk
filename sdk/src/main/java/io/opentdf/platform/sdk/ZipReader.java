package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;

public class ZipReader {

    public class Entry {
        private final String name;
        private final long offset;

        private final long size;

        public Entry(String name, long offset, long size) {
            this.name = name;
            this.offset = offset;
            this.size = size;
        }

        public OutputStream getBytes() {
            return null;
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

    private int numEntries;
    private short fileNameLength;
    private short extraFieldLength;
    private long offsetToStartOfCentralDirectory;

    private CentralDirectoryRecord readEndOfCentralDirectory(ByteBuffer buffer) throws Exception {
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        long fileSize = buffer.capacity();
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
            throw new Exception("Invalid tdf file");
        }

        // Read the EOCDR
        short _diskNumber = buffer.getShort();
        short _centralDirectoryDiskNumber = buffer.getShort();
        short _numEntriesThisDisk = buffer.getShort();
        numEntries = buffer.getShort();
        int _centralDirectorySize = buffer.getInt();
        offsetToStartOfCentralDirectory = buffer.getInt();
        short _commentLength = buffer.getShort();

        // buffer's position at the start of the Central Directory
        if (offsetToStartOfCentralDirectory == ZIP64_MAGICVAL) {
            long index = fileSize - (22+ 20); // 22 is the size of the EOCDR and 20 is the size of the Zip64 EOCDR
            buffer.position((int)index);
            readZip64EndOfCentralDirectoryLocator(buffer);
            index = fileSize  - (22 + 20 + 56); // 56 is the size of the Zip64 EOCDR
            buffer.position((int)index);
            return readZip64EndOfCentralDirectoryRecord(buffer);
        }

        return new CentralDirectoryRecord(numEntries, offsetToStartOfCentralDirectory);
    }

    private void readZip64EndOfCentralDirectoryLocator(ByteBuffer buffer) {
        int signature = buffer.getInt() ;
        if (signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new RuntimeException("Invalid Zip64 End of Central Directory Record Signature");
        }
        int _numberOfDiskWithZip64End = buffer.getInt();
        long _relativeOffsetEndOfZip64EndOfCentralDirectory = buffer.getLong();
        int _totalNumberOfDisks = buffer.getInt();
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
        numEntries = (int)buffer.getLong();
        long centralDirectorySize = buffer.getLong();
        offsetToStartOfCentralDirectory = buffer.getLong();

        return new CentralDirectoryRecord(numEntries, offsetToStartOfCentralDirectory);
    }

    public int getNumEntries() {
        return numEntries;
    }

    public short getFileNameLength() {
        return fileNameLength;
    }

    public short getExtraFieldLength() {
        return extraFieldLength;
    }

    public long getCDOffset() {
        return offsetToStartOfCentralDirectory;
    }

    public long readCentralDirectoryFileHeader(ByteBuffer buffer) {
        System.out.println("Buffer position: " + buffer.position());
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
        fileNameLength = buffer.getShort();
        extraFieldLength = buffer.getShort();
        short fileCommentLength = buffer.getShort();
        short diskNumberStart = buffer.getShort();
        short internalFileAttributes = buffer.getShort();
        int externalFileAttributes = buffer.getInt();
        long relativeOffsetOfLocalHeader = buffer.getInt() ;

        byte[] fileName = new byte[fileNameLength];
        buffer.get(fileName);
        String fileNameString = new String(fileName, StandardCharsets.UTF_8);
////
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
////
        byte[] extraField = new byte[extraFieldLength];
        buffer.get(extraField);

        byte[] fileComment = new byte[fileCommentLength];
        buffer.get(fileComment);
        String fileCommentString = new String(fileComment, StandardCharsets.UTF_8);
        return relativeOffsetOfLocalHeader;
    }

    public void readLocalFileHeader(ByteBuffer buffer) {
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
        String fileNameString = new String(fileName, StandardCharsets.UTF_8);
        System.out.println("File name: " + fileNameString);

        byte[] extraField = new byte[extraFieldLength];
        buffer.get(extraField);

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

    public ZipReader(SeekableByteChannel channel) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(BUFFER_CAPACITY);
        long offset = Math.max(0, channel.size() - BUFFER_CAPACITY);
        channel.position(offset);
        while (channel.read(buf) > 0){}
        buf.flip();

        readCentralDirectoryFileHeader(buf);
    }
}