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

    /**
     * Fills {@code buf} from the channel. {@link SeekableByteChannel#read} may return fewer bytes
     * than asked for while more are still available, so a single read cannot tell "the archive
     * ends here" from "that read came up short" — and taking the second for the first rejects a
     * perfectly good archive. Only a read that reports no progress at all is an end of file.
     *
     * @return false at end of file, in which case {@code buf} holds nothing worth reading
     */
    private boolean fill(ByteBuffer buf) throws IOException {
        buf.clear();
        while (buf.hasRemaining()) {
            if (this.zipChannel.read(buf) <= 0) {
                return false;
            }
        }
        buf.flip();
        return true;
    }

    final ByteBuffer longBuf = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
    private long readLong() throws IOException {
        if (!fill(longBuf)) {
            throw new InvalidZipException("Expected long value");
        }
        return longBuf.getLong();
    }

    final ByteBuffer intBuf = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN);
    private Integer readInteger() throws IOException {
        if (!fill(intBuf)) {
            return null;
        }
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
        if (!fill(shortBuf)) {
            throw new InvalidZipException("Expected short value");
        }
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

    /**
     * The most a comment can push the end of central directory record back from the end of the
     * archive, and so how far back the scan for it has to look. The record is followed by nothing
     * but its own comment, whose length lives in a 2-byte field.
     */
    private static final long MAX_END_OF_CENTRAL_DIRECTORY_COMMENT_SIZE = 0xFFFF;

    /**
     * Positions the channel at an offset that came out of the archive itself. The zip64 records
     * carry offsets as 64-bit values, so a corrupt archive can point anywhere: unchecked, a
     * negative one escapes as an {@link IllegalArgumentException} from the channel rather than as
     * a zip error, and one past the end lands somewhere plausible and fails later with a
     * complaint about whatever happened to be there.
     */
    private void seekWithinArchive(String what, long offset) throws IOException {
        if (offset < 0 || offset >= zipChannel.size()) {
            throw new InvalidZipException(what + " points to offset " + offset
                    + ", which is outside this " + zipChannel.size() + " byte archive");
        }
        zipChannel.position(offset);
    }

    CentralDirectoryRecord readEndOfCentralDirectory() throws IOException {
        long eoCDRStart = zipChannel.size() - END_OF_CENTRAL_DIRECTORY_SIZE; // 22 is the minimum size of the EOCDR
        // a comment is the only thing that can sit between the record and the end of the archive,
        // so there is no reason to look back any further than the longest possible one. an
        // unbounded scan walks the whole archive a byte at a time doing a positioned four byte
        // read per byte — tens of seconds per hundred MiB against a file — before it can report
        // that the archive is not a zip, and it gives a stray signature deep inside a payload a
        // chance to be mistaken for the record
        long earliestPossibleStart = Math.max(0, zipChannel.size()
                - (END_OF_CENTRAL_DIRECTORY_SIZE + MAX_END_OF_CENTRAL_DIRECTORY_COMMENT_SIZE));

        boolean found = false;
        while (eoCDRStart >= earliestPossibleStart) {
            zipChannel.position(eoCDRStart);
            Integer signature = readInteger();
            // readInteger reports an end of file as null, which the bounds of this scan rule out:
            // every offset it probes has a whole record behind it. keep the two cases apart
            // anyway, so that an end of file can never be taken for a match
            if (signature != null && signature == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Found end of central directory signature at {}", zipChannel.position() - Integer.BYTES);
                }
                found = true;
                break;
            }
            eoCDRStart--;
        }

        if (!found) {
            throw new InvalidZipException("Didn't find the end of central directory in the last "
                    + (zipChannel.size() - earliestPossibleStart) + " bytes of this "
                    + zipChannel.size() + " byte archive");
        }

        short diskNumber = readShort();
        short centralDirectoryDiskNumber = readShort();
        short numCDEntriesOnThisDisk = readShort();

        int totalNumEntries = readUnsignedShort();
        long sizeOfCentralDirectory = readUnsignedInt();
        long offsetToStartOfCentralDirectory = readUnsignedInt();
        readUnsignedShort(); // comment length; nothing here reads it, but the field is there

        // any one of these fields may carry the sentinel that sends its real value to the zip64
        // end of central directory record; an archive can need zip64 for its entry count alone
        // while its central directory still starts below 4 GiB. the size is checked for the same
        // reason even though nothing here reads it yet
        if (totalNumEntries != ZIP64_MAGIC_SHORT
                && sizeOfCentralDirectory != ZIP64_MAGICVAL
                && offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
            return new CentralDirectoryRecord(totalNumEntries, offsetToStartOfCentralDirectory);
        }

        // the locator sits immediately before the record we found, so it is measured from there
        // rather than from the end of the archive. the two agree only when nothing follows the
        // record and its comment length is honest; measuring from the end lands at the wrong
        // offset for anything else and blames the locator for it
        long zip64CentralDirectoryLocatorStart = eoCDRStart - ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE;
        if (zip64CentralDirectoryLocatorStart < 0) {
            throw new InvalidZipException(
                    "Archive is too small to hold the zip64 end of central directory locator it claims to have");
        }
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

        seekWithinArchive("the zip64 end of central directory locator", offsetToEndOfCentralDirectory);
        int sig = readInt();
        if (sig != ZIP_64_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
            throw new InvalidZipException("Invalid zip64 end of central directory signature at offset "
                    + offsetToEndOfCentralDirectory + ": expected 0x"
                    + Integer.toHexString(ZIP_64_END_OF_CENTRAL_DIRECTORY_SIGNATURE)
                    + " but found 0x" + Integer.toHexString(sig));
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

        /**
         * Checks that this entry's local header offset points inside the archive, so a corrupt
         * or truncated central directory fails here rather than at an arbitrary position.
         */
        private void checkOffsetToLocalHeader() throws IOException {
            if (offsetToLocalHeader < 0 || offsetToLocalHeader >= zipChannel.size()) {
                throw new InvalidZipException("local header offset out of range for entry ["
                        + fileName + "]: " + offsetToLocalHeader);
            }
        }

        /**
         * Reads this entry's local file header and returns the offset of the first byte of its
         * data. Leaves the channel positioned within the header rather than at the returned
         * offset, because the filename and extra field are skipped by arithmetic.
         */
        private long findStartOfData() throws IOException {
            checkOffsetToLocalHeader();
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

            return zipChannel.position() + filenameLength + extrafieldLength;
        }

        public InputStream getData() throws IOException {
            final long startPosition = findStartOfData();
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
                    buf.clear();
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
        seekWithinArchive("the central directory", centralDirectoryRecord.offsetToStart);
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
