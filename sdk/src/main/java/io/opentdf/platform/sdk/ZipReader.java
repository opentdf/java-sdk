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

    private int numEntries;
    private short fileNameLength;

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
            } else if (signature == ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
                System.out.println("Found Zip64 End of Central Directory Record");
                readZip64EndOfCentralDirectoryRecord(buffer);
                break;
            } else if (signature == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
                System.out.println("Found Zip64 End of Central Directory Locator");
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
        int centralDirectoryOffset = buffer.getInt();
        short commentLength = buffer.getShort();

        // buffer's position at the start of the Central Directory
        buffer.position(centralDirectoryOffset);
    }

    private void readZip64EndOfCentralDirectoryLocator(ByteBuffer buffer) {
        int numberOfDiskWithZip64End = buffer.getInt();
        long relativeOffsetEndOfZip64EndOfCentralDirectory = buffer.getLong();
        int totalNumberOfDisks = buffer.getInt();
    }

    private void readZip64EndOfCentralDirectoryRecord(ByteBuffer buffer) {
        long sizeOfZip64EndOfCentralDirectoryRecord = buffer.getLong();
        short versionMadeBy = buffer.getShort();
        short versionNeededToExtract = buffer.getShort();
        int diskNumber = buffer.getInt();
        int diskWithCentralDirectory = buffer.getInt();
        long numEntriesOnThisDisk = buffer.getLong();
        numEntries = buffer.getInt();
        long centralDirectorySize = buffer.getLong();
        long offsetToStartOfCentralDirectory = buffer.getLong();
    }

    public int getNumEntries() {
        return numEntries;
    }

    public short getFileNameLength() {
        return fileNameLength;
    }

    public int readCentralDirectoryFileHeader(ByteBuffer buffer) {
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
        short extraFieldLength = buffer.getShort();
        short fileCommentLength = buffer.getShort();
        short diskNumberStart = buffer.getShort();
        short internalFileAttributes = buffer.getShort();
        int externalFileAttributes = buffer.getInt();
        int relativeOffsetOfLocalHeader = buffer.getInt();

        byte[] fileName = new byte[fileNameLength];
        buffer.get(fileName);
        String fileNameString = new String(fileName, StandardCharsets.UTF_8);

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

        byte[] extraField = new byte[extraFieldLength];
        buffer.get(extraField);

        byte[] fileData = new byte[compressedSize];
        buffer.get(fileData);

        if (compressionMethod == 0) {
            String fileContent = new String(fileData, StandardCharsets.UTF_8);
            System.out.println("File content: " + fileContent);
        } else {
            System.out.println("File is compressed, need to decompress it first");
        }
    }
}