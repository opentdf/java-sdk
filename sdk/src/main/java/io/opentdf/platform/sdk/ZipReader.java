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
     * How many reads in a row may come back empty before the channel is taken to have stalled.
     */
    private static final int MAX_CONSECUTIVE_EMPTY_READS = 16;

    /**
     * Reads at least one byte into {@code buf}, which must have room for one. Only {@code -1}
     * from {@link SeekableByteChannel#read} means end of file. An occasional {@code 0} is
     * retried, but without waiting: after {@value #MAX_CONSECUTIVE_EMPTY_READS} empty reads in a
     * row this gives up rather than spin. Non-blocking channels are not supported.
     *
     * @return the number of bytes read, which is always positive, or {@code -1} at end of file
     * @throws IOException if the channel keeps returning nothing
     */
    private int readSome(ByteBuffer buf) throws IOException {
        for (int attempt = 0; attempt < MAX_CONSECUTIVE_EMPTY_READS; attempt++) {
            int read = zipChannel.read(buf);
            if (read != 0) {
                return read;
            }
        }
        throw new IOException(zipChannel.getClass().getName() + " returned no data "
                + MAX_CONSECUTIVE_EMPTY_READS + " times in a row at offset " + zipChannel.position()
                + "; ZipReader requires a blocking channel");
    }

    /**
     * Fills {@code buf} from the channel, reading as many times as it takes, since a single
     * {@link SeekableByteChannel#read} may come up short without being at the end of the file.
     *
     * @return false at end of file, in which case {@code buf} holds nothing worth reading
     * @throws IOException if the channel stalls (see {@link #readSome})
     */
    private boolean fill(ByteBuffer buf) throws IOException {
        buf.clear();
        while (buf.hasRemaining()) {
            if (readSome(buf) < 0) {
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
     * The longest comment the end of central directory record can carry, since its length lives
     * in a 2-byte field. This is how far back from the end of the archive the scan for the record
     * looks, so trailing data after the record is tolerated only if it fits in the same window
     * as the comment.
     */
    private static final long MAX_END_OF_CENTRAL_DIRECTORY_COMMENT_SIZE = 0xFFFF;

    /** The fixed part of a central directory file header, before its variable length fields. */
    private static final int CENTRAL_DIRECTORY_FILE_HEADER_MIN_SIZE = 46;

    /**
     * Checks an offset read from the archive, which a corrupt archive can set to anything, in a
     * 32-bit field or a zip64 one. Unchecked, a negative offset escapes as an
     * {@link IllegalArgumentException} from the channel rather than as a zip error, and one at or
     * past the end fails at the next read with a generic complaint that names neither the offset
     * nor the field it came from.
     */
    private void requireWithinArchive(String what, long offset) throws IOException {
        if (offset < 0 || offset >= zipChannel.size()) {
            throw new InvalidZipException(what + " points to offset " + offset
                    + ", which is outside this " + zipChannel.size() + " byte archive");
        }
    }

    /**
     * Positions the channel at an offset read from the archive, once {@link #requireWithinArchive}
     * accepts it.
     */
    private void seekWithinArchive(String what, long offset) throws IOException {
        requireWithinArchive(what, offset);
        zipChannel.position(offset);
    }

    /**
     * Ties a candidate end of central directory record to the central directory it describes. In
     * every archive this reader supports the central directory ends exactly where the record
     * after it begins: the zip64 end of central directory record if there is one, otherwise the
     * end of central directory record itself (APPNOTE 4.3.6). A stray signature in the comment
     * or in trailing data can carry a comment length that fits, so that check alone does not rule
     * it out, but the extent it declares will not land on it.
     *
     * @param recordStart where the record that follows the central directory starts
     */
    private CentralDirectoryRecord centralDirectoryEndingAt(String recordName, long recordStart, long numEntries,
                                                            long offset, long size) throws IOException {
        requireWithinArchive("the " + recordName + " at offset " + recordStart, offset);
        // compared as a difference, since a zip64 size can be large enough to overflow a sum. a
        // zip64 size can also read as negative, which would match a central directory said to
        // start after the record it ends at
        if (size < 0 || size != recordStart - offset) {
            throw new InvalidZipException("The " + recordName + " at offset " + recordStart
                    + " describes a central directory of " + Long.toUnsignedString(size) + " bytes at offset "
                    + offset + ", which does not end where that record starts");
        }
        return new CentralDirectoryRecord(numEntries, offset);
    }

    /**
     * Checks that the comment of a candidate end of central directory record ends inside the
     * archive, as a real record's comment does. This rejects a real record whose comment was cut
     * short, and a stray signature whose length bytes happen to be large. A stray signature with
     * a small declared length gets past it, and is caught by {@link #centralDirectoryEndingAt}
     * instead. Trailing data after the comment is allowed.
     */
    private boolean commentEndsWithinArchive(long eoCDRStart) throws IOException {
        zipChannel.position(eoCDRStart + END_OF_CENTRAL_DIRECTORY_SIZE - Short.BYTES);
        int commentLength = readUnsignedShort();
        return eoCDRStart + END_OF_CENTRAL_DIRECTORY_SIZE + commentLength <= zipChannel.size();
    }

    CentralDirectoryRecord readEndOfCentralDirectory() throws IOException {
        long eoCDRStart = zipChannel.size() - END_OF_CENTRAL_DIRECTORY_SIZE; // 22 is the minimum size of the EOCDR
        // in a conformant archive only the comment follows the record, so the scan stops after the
        // longest possible comment. an unbounded scan does a positioned four byte read for every
        // byte of the archive before it can reject a non-zip, and gives a stray signature deep
        // inside a payload a chance to be mistaken for the record
        long earliestPossibleStart = Math.max(0, zipChannel.size()
                - (END_OF_CENTRAL_DIRECTORY_SIZE + MAX_END_OF_CENTRAL_DIRECTORY_COMMENT_SIZE));

        // a candidate that fails a structural check is passed over, since the scan can meet a stray
        // signature before the real record. if none passes, the failure of the one nearest the
        // end is reported
        InvalidZipException firstRejection = null;
        for (; eoCDRStart >= earliestPossibleStart; eoCDRStart--) {
            zipChannel.position(eoCDRStart);
            Integer signature = readInteger();
            if (signature == null) {
                // every probed offset is at most size - 22, so a whole record's worth of bytes
                // should follow it; an end of file here means the channel holds less than size()
                throw new InvalidZipException("Archive ended at offset " + zipChannel.position()
                        + ", before its reported size of " + zipChannel.size() + " bytes");
            }
            if (signature != END_OF_CENTRAL_DIRECTORY_SIGNATURE || !commentEndsWithinArchive(eoCDRStart)) {
                continue;
            }
            try {
                var centralDirectory = readCentralDirectoryRecord(eoCDRStart);
                logger.debug("Found end of central directory record at {}", eoCDRStart);
                return centralDirectory;
            } catch (InvalidZipException e) {
                logger.debug("Passing over end of central directory signature at {}: {}", eoCDRStart, e.getMessage());
                if (firstRejection == null) {
                    firstRejection = e;
                }
            }
        }

        if (firstRejection != null) {
            throw firstRejection;
        }
        throw new InvalidZipException("Didn't find the end of central directory in the last "
                + (zipChannel.size() - earliestPossibleStart) + " bytes of this "
                + zipChannel.size() + " byte archive");
    }

    /**
     * Reads the candidate end of central directory record at {@code eoCDRStart}, following it to
     * the zip64 record if it has one, and checks that it describes the central directory in front
     * of it.
     */
    private CentralDirectoryRecord readCentralDirectoryRecord(long eoCDRStart) throws IOException {
        zipChannel.position(eoCDRStart + Integer.BYTES);
        short diskNumber = readShort();
        short centralDirectoryDiskNumber = readShort();
        short numCDEntriesOnThisDisk = readShort();

        int totalNumEntries = readUnsignedShort();
        long sizeOfCentralDirectory = readUnsignedInt();
        long offsetToStartOfCentralDirectory = readUnsignedInt();

        // any one of these fields may carry the sentinel that sends its real value to the zip64
        // end of central directory record; an archive can need zip64 for its entry count alone
        // while its central directory still starts below 4 GiB
        if (totalNumEntries != ZIP64_MAGIC_SHORT
                && sizeOfCentralDirectory != ZIP64_MAGICVAL
                && offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
            long zip64RecordStart = zip64RecordStartIfAny(eoCDRStart);
            if (zip64RecordStart >= 0) {
                return centralDirectoryEndingAt("zip64 end of central directory record", zip64RecordStart,
                        totalNumEntries, offsetToStartOfCentralDirectory, sizeOfCentralDirectory);
            }
            return centralDirectoryEndingAt("end of central directory record", eoCDRStart, totalNumEntries,
                    offsetToStartOfCentralDirectory, sizeOfCentralDirectory);
        }

        // the locator immediately precedes the record (APPNOTE 4.3.6), so measure from the record
        // rather than from the end of the archive, which may hold trailing data
        long zip64CentralDirectoryLocatorStart = eoCDRStart - ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE;
        if (zip64CentralDirectoryLocatorStart < 0) {
            throw new InvalidZipException(
                    "Archive is too small to hold the zip64 end of central directory locator it claims to have");
        }
        return extractZIP64CentralDirectoryInfo(zip64CentralDirectoryLocatorStart);
    }

    /**
     * Finds the zip64 end of central directory record of an archive whose end of central directory
     * record carries no sentinel. Some writers, commons-compress among them, add the zip64 records
     * anyway, and then the central directory ends where the zip64 record starts rather than where
     * the end of central directory record does. Nothing else is read from them, since every field
     * the reader needs fit in the end of central directory record.
     *
     * @return where the zip64 record starts, or -1 if a locator in front of {@code eoCDRStart}
     *     doesn't lead to one
     */
    private long zip64RecordStartIfAny(long eoCDRStart) throws IOException {
        long locatorStart = eoCDRStart - ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIZE;
        if (locatorStart < 0) {
            return -1;
        }
        zipChannel.position(locatorStart);
        if (readInt() != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            return -1;
        }
        readInt(); // disk number
        long zip64RecordStart = readLong();
        if (zip64RecordStart < 0 || zip64RecordStart >= locatorStart) {
            return -1;
        }
        zipChannel.position(zip64RecordStart);
        return readInt() == ZIP_64_END_OF_CENTRAL_DIRECTORY_SIGNATURE ? zip64RecordStart : -1;
    }

    private CentralDirectoryRecord extractZIP64CentralDirectoryInfo(long locatorStart) throws IOException {
        zipChannel.position(locatorStart);
        Integer signature = readInteger();
        if (signature == null || signature != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE) {
            throw new InvalidZipException("Invalid zip64 end of central directory locator signature at offset "
                    + locatorStart + ": expected 0x"
                    + Integer.toHexString(ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE)
                    + " but found " + (signature == null ? "the end of the archive" : "0x" + Integer.toHexString(signature)));
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

        return centralDirectoryEndingAt("zip64 end of central directory record", offsetToEndOfCentralDirectory,
                totalNumCDEntries, cdOffset, cdSize);
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
         * The uncompressed size the central directory records for this entry. It comes from the
         * archive and is not checked against the data, so treat it as a claim: it lets a caller
         * refuse an entry too large to buffer before reading any of it.
         */
        long getSize() {
            return fileSize;
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
                throw new InvalidZipException("Invalid local file header signature for entry [" + fileName
                        + "] at offset " + offsetToLocalHeader + ": "
                        + (signature == null ? "the archive ends there" : "found 0x" + Integer.toHexString(signature)));
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
                    if (readSome(buf) < 0) {
                        throw truncated();
                    }
                    offset += 1;
                    return buf.array()[0] & 0xFF;
                }

                private boolean doneReading() {
                    return offset >= fileSize;
                }

                // Moves the cursor without reading: the default skip reads and discards, which
                // over HTTP would download everything skipped.
                @Override
                public long skip(long n) {
                    long skipped = Math.max(0, Math.min(n, fileSize - offset));
                    offset += skipped;
                    return skipped;
                }

                /**
                 * The archive ended before this entry's data did. Reporting that as an ordinary
                 * end of stream would hand the caller a short entry with no sign anything is wrong.
                 */
                private InvalidZipException truncated() {
                    return new InvalidZipException("Archive ended " + offset + " bytes into the "
                            + fileSize + " byte entry [" + fileName + "]");
                }

                private void setChannelPosition() throws IOException {
                    var nextPosition = startPosition + offset;
                    if (zipChannel.position() != nextPosition) {
                        zipChannel.position(nextPosition);
                    }
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    if (len == 0) {
                        return 0;
                    }
                    if (doneReading()) {
                        return -1;
                    }
                    setChannelPosition();
                    var lenToRead = (int)Math.min(len, fileSize - offset); // cast is always valid because len is an int
                    var buf = ByteBuffer.wrap(b, off, lenToRead);
                    // InputStream must not return 0 for a non-empty request, so this has to wait
                    // for at least one byte rather than pass an empty channel read through
                    var nread = readSome(buf);
                    if (nread < 0) {
                        throw truncated();
                    }
                    offset += nread;
                    return nread;
                }
            };
        }
    }

    /** Each extra field record starts with a 2-byte id and a 2-byte data size. */
    private static final int EXTRA_FIELD_HEADER_SIZE = 4;

    /**
     * Checks that a {@code size} byte value read at the current position stays inside the zip64
     * extra field record ending at {@code fieldEnd}. A record too short for the values its
     * sentinels promise would otherwise be read past, into whatever follows it.
     */
    private void requireWithinField(String what, int size, long fieldEnd, long headerStart) throws IOException {
        if (zipChannel.position() + size > fieldEnd) {
            throw new InvalidZipException("The zip64 extra field of the central directory file header at offset "
                    + headerStart + " is too short to hold the " + what + " its sentinel promises");
        }
    }

    /**
     * Reads one 8-byte value out of a zip64 extra field record. The format calls these unsigned,
     * but nothing can be larger than {@link Long#MAX_VALUE} bytes, so a value that comes out
     * negative as a Java {@code long} is a corrupt or hostile archive rather than a big one.
     */
    private long readZip64Value(String what, long fieldEnd, long headerStart) throws IOException {
        requireWithinField(what, Long.BYTES, fieldEnd, headerStart);
        long value = readLong();
        if (value < 0) {
            throw new InvalidZipException("The zip64 " + what + " of the central directory file header at offset "
                    + headerStart + " is " + Long.toUnsignedString(value) + ", which no archive can hold");
        }
        return value;
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

        long fileNameStart = zipChannel.position();
        ByteBuffer fileName = ByteBuffer.allocate(fileNameLength);
        if (!fill(fileName)) {
            throw new InvalidZipException("Archive ended inside the " + fileNameLength
                    + " byte filename of the central directory file header at offset "
                    + (fileNameStart - CENTRAL_DIRECTORY_FILE_HEADER_MIN_SIZE));
        }

        long headerStart = fileNameStart - CENTRAL_DIRECTORY_FILE_HEADER_MIN_SIZE;
        long extraFieldStart = zipChannel.position();
        long extraFieldEnd = extraFieldStart + extraFieldLength;
        if (extraFieldEnd > zipChannel.size()) {
            throw new InvalidZipException("The " + extraFieldLength + " byte extra field of the central directory"
                    + " file header at offset " + headerStart + " runs past the end of this "
                    + zipChannel.size() + " byte archive");
        }

        // walk the extra field as a sequence of (id, size, data) records. each step moves past a
        // whole record, header included, so the walk always advances, and no record may claim
        // more bytes than are left in the extra field. a sign-extended or oversized data size
        // used to send the position backwards or beyond the field, looping forever or reading
        // the next header as if it were part of this one
        long fieldStart = extraFieldStart;
        while (extraFieldEnd - fieldStart >= EXTRA_FIELD_HEADER_SIZE) {
            zipChannel.position(fieldStart);
            int headerId = readUnsignedShort();
            int dataSize = readUnsignedShort();
            long dataStart = fieldStart + EXTRA_FIELD_HEADER_SIZE;
            long dataEnd = dataStart + dataSize;
            if (dataEnd > extraFieldEnd) {
                throw new InvalidZipException("Extra field 0x" + Integer.toHexString(headerId) + " of the central"
                        + " directory file header at offset " + headerStart + " claims " + dataSize
                        + " bytes, but only " + (extraFieldEnd - dataStart) + " remain in the extra field");
            }

            if (headerId == ZIP64_EXTID) {
                // APPNOTE 4.5.3 order: original size, compressed size, then local header offset
                if (uncompressedSize == ZIP64_MAGICVAL) {
                    uncompressedSize = readZip64Value("uncompressed size", dataEnd, headerStart);
                }
                if (compressedSize == ZIP64_MAGICVAL) {
                    compressedSize = readZip64Value("compressed size", dataEnd, headerStart);
                }
                if (relativeOffsetOfLocalHeader == ZIP64_MAGICVAL) {
                    relativeOffsetOfLocalHeader = readZip64Value("local header offset", dataEnd, headerStart);
                }
                // a 2-byte field, so its sentinel is 0xFFFF rather than 0xFFFFFFFF
                if (diskNumberStart == ZIP64_MAGIC_SHORT) {
                    requireWithinField("disk number", Integer.BYTES, dataEnd, headerStart);
                    diskNumberStart = readInt();
                }
            }
            fieldStart = dataEnd;
        }
        // fewer bytes than a record header may be left over; like other readers, ignore them

        long fileCommentEnd = extraFieldEnd + fileCommentLength;
        if (fileCommentEnd > zipChannel.size()) {
            throw new InvalidZipException("The " + fileCommentLength + " byte comment of the central directory"
                    + " file header at offset " + headerStart + " runs past the end of this "
                    + zipChannel.size() + " byte archive");
        }
        // an honest archive stores every byte of an entry's data after its local header, so an
        // entry that claims to start or end beyond the archive cannot be read. the uncompressed
        // size is left to the reader, which reports a short entry as truncated when it gets there
        if (relativeOffsetOfLocalHeader >= zipChannel.size()
                || compressedSize > zipChannel.size() - relativeOffsetOfLocalHeader) {
            throw new InvalidZipException("Entry [" + new String(fileName.array(), StandardCharsets.UTF_8)
                    + "] claims " + compressedSize + " bytes at local header offset " + relativeOffsetOfLocalHeader
                    + ", which does not fit in this " + zipChannel.size() + " byte archive");
        }
        zipChannel.position(fileCommentEnd);

        return new Entry(fileName.array(), relativeOffsetOfLocalHeader, uncompressedSize);
    }

    public ZipReader(SeekableByteChannel channel) throws IOException {
        zipChannel = channel;
        var centralDirectoryRecord = readEndOfCentralDirectory();
        seekWithinArchive("the central directory", centralDirectoryRecord.offsetToStart);
        // a corrupt zip64 count can be negative, which would read as an empty archive, or more
        // than the rest of the archive can hold, which would read past the central directory
        long bytesAvailable = zipChannel.size() - centralDirectoryRecord.offsetToStart;
        long mostEntriesThatFit = bytesAvailable / CENTRAL_DIRECTORY_FILE_HEADER_MIN_SIZE;
        if (centralDirectoryRecord.numEntries < 0 || centralDirectoryRecord.numEntries > mostEntriesThatFit) {
            throw new InvalidZipException("The central directory claims " + centralDirectoryRecord.numEntries
                    + " entries, but the " + bytesAvailable + " bytes from its start to the end of the archive"
                    + " can hold at most " + mostEntriesThatFit);
        }
        for (long i = 0; i < centralDirectoryRecord.numEntries; i++) {
            entries.add(readCentralDirectoryFileHeader());
        }
    }

    final SeekableByteChannel zipChannel;
    final ArrayList<Entry> entries = new ArrayList<>();

    public List<Entry> getEntries() {
        return entries;
    }
}
