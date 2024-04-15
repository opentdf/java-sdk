package io.opentdf.platform.sdk;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class ZipReader {
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
    private long relativeOffsetEndOfZip64EndOfCentralDirectory;

    public void readEndOfCentralDirectory(ByteBuffer buffer) throws Exception {
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
        short diskNumber = buffer.getShort();
        short centralDirectoryDiskNumber = buffer.getShort();
        short numEntriesThisDisk = buffer.getShort();
        numEntries = buffer.getShort();
        int centralDirectorySize = buffer.getInt();
        offsetToStartOfCentralDirectory = buffer.getInt();
        short commentLength = buffer.getShort();

        // buffer's position at the start of the Central Directory
        boolean isZip64 = false;
        if (offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
            //buffer.position((int)offsetToStartOfCentralDirectory);
        } else {
            isZip64 = true;
            long index = fileSize - (22+ 20); // 22 is the size of the EOCDR and 20 is the size of the Zip64 EOCDR
            buffer.position((int)index);
            readZip64EndOfCentralDirectoryLocator(buffer);
            index = fileSize  - (22 + 20 + 56); // 56 is the size of the Zip64 EOCDR
            buffer.position((int)index);
            readZip64EndOfCentralDirectoryRecord(buffer);
            //buffer.position((int)offsetToStartOfCentralDirectory);
        }
        // buffer.position(centralDirectoryOffset);
    }

    private void readZip64EndOfCentralDirectoryLocator(ByteBuffer buffer) {
        int signature = buffer.getInt() ;
        if (signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new RuntimeException("Invalid Zip64 End of Central Directory Record Signature");
        }
        int numberOfDiskWithZip64End = buffer.getInt();
        relativeOffsetEndOfZip64EndOfCentralDirectory = buffer.getLong();
        int totalNumberOfDisks = buffer.getInt();
    }

    private void readZip64EndOfCentralDirectoryRecord(ByteBuffer buffer) {
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
}