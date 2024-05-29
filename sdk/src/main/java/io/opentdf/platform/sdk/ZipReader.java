package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ZipReader {

    public static final Logger logger = LoggerFactory.getLogger(ZipReader.class);
    public static final int END_OF_CENTRAL_DIRECTORY_SIZE = 22;
    public static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE = 20;

    final ByteBuffer longBuf = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
    private Long readLong() throws IOException {
        longBuf.clear();
        if (this.zipChannel.read(longBuf) != 8) {
            return null;
        }
        longBuf.flip();
        return longBuf.getLong();
    }

    final ByteBuffer intBuf = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN);
    private Integer readInt() throws IOException {
        intBuf.clear();
        if (this.zipChannel.read(intBuf) != 4) {
            return null;
        }
        intBuf.flip();
        return intBuf.getInt();
    }

    final ByteBuffer shortBuf = ByteBuffer.allocate(Short.BYTES).order(ByteOrder.LITTLE_ENDIAN);

    private Short readShort() throws IOException {
        shortBuf.clear();
        if (this.zipChannel.read(shortBuf) != 2) {
            return null;
        }
        shortBuf.flip();
        return shortBuf.getShort();
    }

    private static class CentralDirectoryRecord {
        final long numEntries;
        final long offsetToStart;

        public CentralDirectoryRecord(long numEntries, long offsetToStart) {
            this.numEntries = numEntries;
            this.offsetToStart = offsetToStart;
        }
    }

    private static final int ZIP_64_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06064b50;
    private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
    private static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE = 0x07064b50;
    private static final int CENTRAL_FILE_HEADER_SIGNATURE =  0x02014b50;

    private static final int LOCAL_FILE_HEADER_SIGNATURE =  0x04034b50;
    private static final int ZIP64_MAGICVAL = 0xFFFFFFFF;
    private static final int ZIP64_EXTID= 0x0001;

    CentralDirectoryRecord readEndOfCentralDirectory() throws IOException {
        long eoCDRStart = zipChannel.size() - END_OF_CENTRAL_DIRECTORY_SIZE; // 22 is the minimum size of the EOCDR

        while (eoCDRStart >= 0) {
            zipChannel.position(eoCDRStart);
            int signature = readInt();
            if (signature == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Found end of central directory signature at {}", zipChannel.position() - Integer.BYTES);
                }
                break;
            }
            eoCDRStart--;
        }

        if (eoCDRStart < 0) {
            throw new RuntimeException("Didn't find the end of central directory");
        }

        short diskNumber = readShort();
        short centralDirectoryDiskNumber = readShort();
        short numCDEntriesOnThisDisk = readShort();

        int totalNumEntries = readShort();
        int sizeOfCentralDirectory = readInt();
        long offsetToStartOfCentralDirectory = readInt();
        short commentLength = readShort();

        if (offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
            return new CentralDirectoryRecord(totalNumEntries, offsetToStartOfCentralDirectory);
        }

        long zip64CentralDirectoryLocatorStart = zipChannel.size() - (ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE + END_OF_CENTRAL_DIRECTORY_SIZE + commentLength);
        zipChannel.position(zip64CentralDirectoryLocatorStart);
        return extractZIP64CentralDirectoryInfo();
    }

    private CentralDirectoryRecord extractZIP64CentralDirectoryInfo() throws IOException {
        // buffer's position at the start of the Central Directory
        int signature = readInt();
        if (signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new RuntimeException("Invalid Zip64 End of Central Directory Record Signature");
        }

        int centralDirectoryDiskNumber = readInt();
        long offsetToEndOfCentralDirectory = readLong();
        int totalNumberOfDisks = readInt();

        zipChannel.position(offsetToEndOfCentralDirectory);
        int sig = readInt();
        if (sig != ZIP_64_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
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

            final long startPosition = zipChannel.position() + filenameLength + extrafieldLength;
            final long endPosition = startPosition + fileSize;
            final ByteBuffer buf = ByteBuffer.allocate(1);
            return new InputStream() {
                long offset = 0;
                @Override
                public int read() throws IOException {
                    if (doneReading()) {
                        return -1;
                    }
                    setChannelPosition();
                    while (buf.position() != buf.capacity()) {
                        if (zipChannel.read(buf) < 0) {
                            return -1;
                        }
                    }
                    offset += 1;
                    return buf.array()[0] & 0xFF;
                }

                private boolean doneReading() {
                    return offset >= fileSize;
                }

                private void setChannelPosition() throws IOException {
                    var nextPosition = startPosition + offset;
                    if (zipChannel.position() != nextPosition) {
                        zipChannel.position(nextPosition);
                    }
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    if (doneReading()) {
                        return -1;
                    }
                    setChannelPosition();
                    var lenToRead = (int)Math.min(len, fileSize - offset); // cast is always valid because len is an int
                    var buf = ByteBuffer.wrap(b, off, lenToRead);
                    var nread = zipChannel.read(buf);
                    if (nread > 0) {
                        offset += nread;
                    }
                    return nread;
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
        int diskNumberStart = readShort();
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
                    compressedSize = readLong();
                }
                if (uncompressedSize == -1) {
                    uncompressedSize = readLong();
                }
                if (relativeOffsetOfLocalHeader == -1) {
                    relativeOffsetOfLocalHeader = readLong();
                }
                if (diskNumberStart == ZIP64_MAGICVAL) {
                    diskNumberStart = readInt();
                }
            }
            // Skip other extra fields
            zipChannel.position(fieldStart + dataSize + 4);
        }

        zipChannel.position(zipChannel.position() + fileCommentLength);

        return new Entry(fileName.array(), relativeOffsetOfLocalHeader, uncompressedSize);
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