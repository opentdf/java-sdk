package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ZipReader {

    public static final int END_OF_CENTRAL_DIRECTORY_SIZE = 22;
    public static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE = 20;

    private Long readLong() throws IOException {
        ByteBuffer intBuf = ByteBuffer.allocate(8);
        intBuf.order(ByteOrder.LITTLE_ENDIAN);
        if (this.zipChannel.read(intBuf) != 8) {
            return null;
        }
        intBuf.flip();
        return intBuf.getLong();
    }

    private Integer readInt() throws IOException {
        ByteBuffer intBuf = ByteBuffer.allocate(4);
        intBuf.order(ByteOrder.LITTLE_ENDIAN);
        if (this.zipChannel.read(intBuf) != 4) {
            return null;
        }
        intBuf.flip();
        return intBuf.getInt();
    }

    private Short readShort() throws IOException {
        ByteBuffer intBuf = ByteBuffer.allocate(2);
        intBuf.order(ByteOrder.LITTLE_ENDIAN);
        if (this.zipChannel.read(intBuf) != 2) {
            return null;
        }
        intBuf.flip();
        return intBuf.getShort();
    }

    private static class CentralDirectoryRecord {
        final long numEntries;
        final long offsetToStart;

        public CentralDirectoryRecord(long numEntries, long offsetToStart) {
            this.numEntries = numEntries;
            this.offsetToStart = offsetToStart;
        }
    }

    private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
    private static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE = 0x07064b50;
    private static final int CENTRAL_FILE_HEADER_SIGNATURE =  0x02014b50;

    private static final int LOCAL_FILE_HEADER_SIGNATURE =  0x04034b50;
    private static final int ZIP64_MAGICVAL = 0xFFFFFFFF;
    private static final int ZIP64_EXTID= 0x0001;

    CentralDirectoryRecord readEndOfCentralDirectory() throws IOException {
        long eoCDRStart = zipChannel.size() - 22; // 22 is the minimum size of the EOCDR

        // Search for the EOCDR from the end of the file
        while (eoCDRStart >= 0) {
            zipChannel.position(eoCDRStart);
            int signature = readInt();
            if (signature == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
                System.out.println("Found End of Central Directory Record");
                break;
            }
            eoCDRStart--;
        }

        if (eoCDRStart < 0) {
            throw new RuntimeException("Invalid tdf file");
        }

        zipChannel.position(zipChannel.position()
                + Short.BYTES  // this disk number
                + Short.BYTES  // disk number that central directory starts on
        );

        zipChannel.position(zipChannel.position()
                + Short.BYTES // number of entries on this disk
        );
        int numEntries = readShort();
        zipChannel.position(zipChannel.position()
                + Integer.BYTES // skip the size of the central directory
        );
        long offsetToStartOfCentralDirectory = readInt();
        short commentLength = readShort();

        if (offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
            return new CentralDirectoryRecord(numEntries, offsetToStartOfCentralDirectory);
        }

        // buffer's position at the start of the Central Directory
        long zip64CentralDirectoryLocatorStart = zipChannel.size() - (ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE + END_OF_CENTRAL_DIRECTORY_SIZE + commentLength);
        zipChannel.position(zip64CentralDirectoryLocatorStart);
        int signature = readInt();
        if (signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new RuntimeException("Invalid Zip64 End of Central Directory Record Signature");
        }

        int centralDirectoryDiskNumber = readInt();
        long offsetToEndOfCentralDirectory = readLong();
        int totalNumberOfDisks = readInt();

        zipChannel.position(offsetToEndOfCentralDirectory);
        int sig = readInt();
        if (sig != 0x06064b50) {
            throw new RuntimeException("Invalid");
        }
        long sizeOfEndOfCentralDirectoryRecord = readLong();
        short versionMadeBy = readShort();
        short versionNeeded = readShort();
        int thisDiskNumber = readInt();
        int cdDiskNumber = readInt();
        long numCDEntriesOnThisDisk = readLong();
        long totalNumCDEntries = readLong();
        long cdSize = readLong();
        long cdOffset = readLong();

        return new CentralDirectoryRecord(totalNumCDEntries, cdOffset);

    }

    public class Entry {
        private final long fileSize;
        private final String fileName;
        final long offsetToLocalHeader;

        private Entry(byte[] fileName, long offsetToLocalHeader, long fileSize) {
            this.fileName = new String(fileName, StandardCharsets.UTF_8);
            this.offsetToLocalHeader = offsetToLocalHeader;
            this.fileSize = fileSize;
        }

        public String getName() {
            return fileName;
        }

        public InputStream getData() throws IOException {
            zipChannel.position(offsetToLocalHeader);
            if (readInt() != LOCAL_FILE_HEADER_SIGNATURE) {
                throw new RuntimeException("Invalid Local Header Signature");
            }
            zipChannel.position(zipChannel.position()
                    + Short.BYTES
                    + Short.BYTES
                    + Short.BYTES
                    + Short.BYTES
                    + Short.BYTES
                    + Integer.BYTES);

            long compressedSize = readInt();
            long uncompressedSize = readInt();
            int filenameLength = readShort();
            int extrafieldLength = readShort();

            zipChannel.position(zipChannel.position() + filenameLength + extrafieldLength);

            final long startPosition = zipChannel.position();

            return new InputStream() {
                long position = zipChannel.position();
                @Override
                public int read() throws IOException {
                    if (position >= startPosition + fileSize) {
                        return -1;
                    }
                    if (zipChannel.position() != position) {
                        zipChannel.position(position);
                    }
                    var buf = ByteBuffer.allocate(1);
                    while (buf.position() != buf.capacity()) {
                        zipChannel.read(buf);
                    }
                    position += 1;
                    return buf.array()[0] & 0xFF;
                }
            };
        }
    }
    public Entry readCentralDirectoryFileHeader() throws IOException {
        int signature = readInt();
        if (signature != CENTRAL_FILE_HEADER_SIGNATURE) {
            throw new RuntimeException("Invalid Central Directory File Header Signature");
        }
        short versionMadeBy = readShort();
        short versionNeededToExtract = readShort();
        short generalPurposeBitFlag = readShort();
        short compressionMethod = readShort();
        short lastModFileTime = readShort();
        short lastModFileDate = readShort();
        int crc32 = readInt();
        long compressedSize = readInt();
        long uncompressedSize = readInt();
        int fileNameLength = readShort();
        int extraFieldLength = readShort();
        short fileCommentLength = readShort();
        short diskNumberStart = readShort();
        short internalFileAttributes = readShort();
        int externalFileAttributes = readInt();
        long relativeOffsetOfLocalHeader = readInt();

        ByteBuffer fileName = ByteBuffer.allocate(fileNameLength);
        while (fileName.position() != fileName.capacity()) {
            zipChannel.read(fileName);
        }

        // Parse the extra field
        for (final long startPos = zipChannel.position(); zipChannel.position() < startPos + extraFieldLength; ) {
            long fieldStart = zipChannel.position();
            int headerId = readShort();
            int dataSize = readShort();

            if (headerId == ZIP64_EXTID) {
                if (compressedSize == -1) {
                    compressedSize = readLong().intValue();
                }
                if (uncompressedSize == -1) {
                    uncompressedSize = readLong().intValue();
                }
                if (relativeOffsetOfLocalHeader == -1) {
                    relativeOffsetOfLocalHeader = readLong().intValue();
                }
                if (diskNumberStart == ZIP64_MAGICVAL) {
                    diskNumberStart = readInt().shortValue();
                }
            }
            // Skip other extra fields
            zipChannel.position(fieldStart + dataSize + 4);
        }

        zipChannel.position(zipChannel.position() + fileCommentLength);

        return new Entry(fileName.array(), relativeOffsetOfLocalHeader, uncompressedSize);
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


    public ZipReader(SeekableByteChannel channel) throws IOException {
        zipChannel = channel;
        var centralDirectoryRecord = readEndOfCentralDirectory();
        zipChannel.position(centralDirectoryRecord.offsetToStart);
        for (int i = 0; i < centralDirectoryRecord.numEntries; i++) {
            entries.add(readCentralDirectoryFileHeader());
        }
    }
    
    final SeekableByteChannel zipChannel;
    final ArrayList<Entry> entries = new ArrayList<>();

    public List<Entry> getEntries() {
        return entries;
    }
}