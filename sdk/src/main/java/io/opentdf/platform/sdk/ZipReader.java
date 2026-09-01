package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The ZipReader class provides functionality to read basic ZIP file
 * structures, such as the End of Central Directory Record and the
 * Local File Header. This class supports standard ZIP archives as well
 * as ZIP64 format.
 */
public class ZipReader {

    public static final Logger logger = LoggerFactory.getLogger(ZipReader.class);
    public static final int END_OF_CENTRAL_DIRECTORY_SIZE = 22;
    public static final int ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE = 20;

    final ByteBuffer longBuf = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
    private long readLong() throws IOException {
        longBuf.clear();
        if (this.zipChannel.read(longBuf) != 8) {
            throw new InvalidZipException("Expected long value");
        }
        longBuf.flip();
        return longBuf.getLong();
    }

    final ByteBuffer intBuf = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN);
    private Integer readInteger() throws IOException {
        intBuf.clear();
        if (this.zipChannel.read(intBuf) != 4) {
            return null;
        }
        intBuf.flip();
        return intBuf.getInt();
    }
    private int readInt() throws IOException {
        Integer result = readInteger();
        if (result == null) {
            throw new InvalidZipException("Expected int value");
        }
        return result.intValue();
    }

    /**
     * Reads a 32-bit zip field as the unsigned value it is on the wire. {@link #readInt()}
     * sign-extends, which silently turns offsets and sizes at or above 2 GiB into negative
     * numbers.
     */
    private long readUnsignedInt() throws IOException {
        return readInt() & 0xFFFFFFFFL;
    }

    final ByteBuffer shortBuf = ByteBuffer.allocate(Short.BYTES).order(ByteOrder.LITTLE_ENDIAN);

    private short readShort() throws IOException {
        shortBuf.clear();
        if (this.zipChannel.read(shortBuf) != 2) {
            throw new InvalidZipException("Expected short value");
        }
        shortBuf.flip();
        return shortBuf.getShort();
    }

    /**
     * Reads a 16-bit zip field as the unsigned value it is on the wire. See
     * {@link #readUnsignedInt()}.
     */
    private int readUnsignedShort() throws IOException {
        return readShort() & 0xFFFF;
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
    /** Sentinel written into a 32-bit field whose real value lives in the zip64 extra field. */
    private static final long ZIP64_MAGICVAL = 0xFFFFFFFFL;
    /** The same sentinel for a 16-bit field, which is only two bytes wide. */
    private static final int ZIP64_MAGIC_SHORT = 0xFFFF;
    private static final int ZIP64_EXTID= 0x0001;

    CentralDirectoryRecord readEndOfCentralDirectory() throws IOException {
        long eoCDRStart = zipChannel.size() - END_OF_CENTRAL_DIRECTORY_SIZE; // 22 is the minimum size of the EOCDR

        while (eoCDRStart >= 0) {
            zipChannel.position(eoCDRStart);
            Integer signature = readInteger();
            if (signature == null || signature == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Found end of central directory signature at {}", zipChannel.position() - Integer.BYTES);
                }
                break;
            }
            eoCDRStart--;
        }

        if (eoCDRStart < 0) {
            throw new InvalidZipException("Didn't find the end of central directory");
        }

        short diskNumber = readShort();
        short centralDirectoryDiskNumber = readShort();
        short numCDEntriesOnThisDisk = readShort();

        int totalNumEntries = readUnsignedShort();
        long sizeOfCentralDirectory = readUnsignedInt();
        long offsetToStartOfCentralDirectory = readUnsignedInt();
        int commentLength = readUnsignedShort();

        if (offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
            return new CentralDirectoryRecord(totalNumEntries, offsetToStartOfCentralDirectory);
        }

        long zip64CentralDirectoryLocatorStart = zipChannel.size() - (ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE + END_OF_CENTRAL_DIRECTORY_SIZE + commentLength);
        zipChannel.position(zip64CentralDirectoryLocatorStart);
        return extractZIP64CentralDirectoryInfo();
    }

    private CentralDirectoryRecord extractZIP64CentralDirectoryInfo() throws IOException {
        // buffer's position at the start of the Central Directory
        Integer signature = readInteger();
        if (signature == null || signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new InvalidZipException("Invalid Zip64 End of Central Directory Record Signature");
        }

        int centralDirectoryDiskNumber = readInt();
        long offsetToEndOfCentralDirectory = readLong();
        int totalNumberOfDisks = readInt();

        zipChannel.position(offsetToEndOfCentralDirectory);
        int sig = readInt();
        if (sig != ZIP_64_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
            throw new InvalidZipException("Invalid");
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
            if (offsetToLocalHeader < 0 || offsetToLocalHeader >= zipChannel.size()) {
                throw new InvalidZipException("local header offset out of range for entry ["
                        + fileName + "]: " + offsetToLocalHeader);
            }
            zipChannel.position(offsetToLocalHeader);
            Integer signature = readInteger();
            if (signature == null || signature != LOCAL_FILE_HEADER_SIGNATURE) {
                throw new InvalidZipException("Invalid Local Header Signature");
            }
            zipChannel.position(zipChannel.position()
                    + Short.BYTES
                    + Short.BYTES
                    + Short.BYTES
                    + Short.BYTES
                    + Short.BYTES
                    + Integer.BYTES);

            long compressedSize = readUnsignedInt();
            long uncompressedSize = readUnsignedInt();
            int filenameLength = readUnsignedShort();
            int extrafieldLength = readUnsignedShort();

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
                    while (buf.hasRemaining()) {
                        if (zipChannel.read(buf) <= 0) {
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
        Integer signature = readInteger();
        if (signature == null || signature != CENTRAL_FILE_HEADER_SIGNATURE) {
            throw new InvalidZipException("Invalid Central Directory File Header Signature");
        }
        short versionMadeBy = readShort();
        short versionNeededToExtract = readShort();
        short generalPurposeBitFlag = readShort();
        short compressionMethod = readShort();
        short lastModFileTime = readShort();
        short lastModFileDate = readShort();
        int crc32 = readInt();
        long compressedSize = readUnsignedInt();
        long uncompressedSize = readUnsignedInt();
        int fileNameLength = readUnsignedShort();
        int extraFieldLength = readUnsignedShort();
        int fileCommentLength = readUnsignedShort();
        int diskNumberStart = readUnsignedShort();
        short internalFileAttributes = readShort();
        int externalFileAttributes = readInt();
        long relativeOffsetOfLocalHeader = readUnsignedInt();

        ByteBuffer fileName = ByteBuffer.allocate(fileNameLength);
        while (fileName.hasRemaining()) {
            if (zipChannel.read(fileName) <= 0) {
                throw new EOFException("Unexpected EOF when reading filename of length: " + fileNameLength);
            }
        }

        // Parse the extra field
        for (final long startPos = zipChannel.position(); zipChannel.position() < startPos + extraFieldLength; ) {
            long fieldStart = zipChannel.position();
            int headerId = readUnsignedShort();
            int dataSize = readUnsignedShort();

            if (headerId == ZIP64_EXTID) {
                // APPNOTE 4.5.3 order: original size, compressed size, then local header offset
                if (uncompressedSize == ZIP64_MAGICVAL) {
                    uncompressedSize = readLong();
                }
                if (compressedSize == ZIP64_MAGICVAL) {
                    compressedSize = readLong();
                }
                if (relativeOffsetOfLocalHeader == ZIP64_MAGICVAL) {
                    relativeOffsetOfLocalHeader = readLong();
                }
                // a 2-byte field, so its sentinel is 0xFFFF rather than 0xFFFFFFFF
                if (diskNumberStart == ZIP64_MAGIC_SHORT) {
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
