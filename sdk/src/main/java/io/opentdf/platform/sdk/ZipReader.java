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
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * The ZipReader class provides functionality to read basic ZIP file
 * structures, such as the End of Central Directory Record and the
 * Local File Header. This class supports standard ZIP archives as well
 * as ZIP64 format, with entries that are stored (method 0) or deflated
 * (method 8). Entry sizes are taken from the central directory.
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
    /** Compression method 0: the entry's bytes are written as they are. All OpenTDF writers use it. */
    private static final int STORED = 0;
    /** Compression method 8: raw DEFLATE (RFC 1951), which some other TDF writers use. */
    private static final int DEFLATED = 8;
    /**
     * The least uncompressed size a deflated entry may declare, however small the archive: 10 MiB.
     * Past it, an entry may declare no more than the archive's length. A deflated TDF payload is
     * ciphertext, which does not compress, so it never declares more than the archive holds;
     * the floor leaves room for a manifest that compresses well.
     */
    private static final long DEFLATED_SIZE_BUDGET_FLOOR = 10L * 1024 * 1024;

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

        // any one of these fields may carry the sentinel that sends its real value to the zip64
        // end of central directory record; an archive can need zip64 for its entry count alone
        // while its central directory still starts below 4 GiB. the size is checked for the same
        // reason even though nothing here reads it yet
        if (totalNumEntries != ZIP64_MAGIC_SHORT
                && sizeOfCentralDirectory != ZIP64_MAGICVAL
                && offsetToStartOfCentralDirectory != ZIP64_MAGICVAL) {
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
        private final long compressedSize;
        private final int compressionMethod;
        private final String fileName;
        final long offsetToLocalHeader;

        private Entry(byte[] fileName, long offsetToLocalHeader, int compressionMethod, long compressedSize,
                      long uncompressedSize) {
            this.fileName = new String(fileName, StandardCharsets.UTF_8);
            this.offsetToLocalHeader = offsetToLocalHeader;
            this.compressionMethod = compressionMethod;
            this.compressedSize = compressedSize;
            this.fileSize = uncompressedSize;
        }

        public String getName() {
            return fileName;
        }

        int getCompressionMethod() {
            return compressionMethod;
        }

        long getCompressedSize() {
            return compressedSize;
        }

        long getUncompressedSize() {
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

        /**
         * Opens this entry's contents. A stored entry is read straight from the archive; a
         * deflated one is inflated as it is read, never past the uncompressed size the central
         * directory declares. Any other compression method is refused here, so an archive whose
         * other entries use one can still be listed and those entries left unread.
         * <p>
         * A deflated entry may not declare an uncompressed size larger than the larger of the
         * archive's length and 10 MiB. Inflation never passes the declared size, so this is what
         * bounds how far a small archive can expand.
         * <p>
         * Entries share the archive's channel. Each stream positions the channel itself on every
         * read, so streams over different entries may be interleaved, but a stream must not be
         * used from more than one thread at a time. Close a deflated entry's stream to release its
         * inflater.
         *
         * @return the entry's uncompressed bytes
         * @throws InvalidZipException if the entry uses a compression method other than stored
         *         or deflate, declares a deflated size over its budget, or its local header is
         *         invalid. A deflated stream also throws it from {@code read} when its data is
         *         corrupt or does not inflate to exactly the declared uncompressed size.
         */
        public InputStream getData() throws IOException {
            long startOfData = checkReadable();
            if (compressionMethod == DEFLATED) {
                return new InflatingInputStream(channelStream(startOfData, compressedSize), fileSize, fileName);
            }
            return channelStream(startOfData, fileSize);
        }

        /**
         * Makes every check {@link #getData()} makes, without opening a stream or allocating an
         * inflater, so a reader can refuse an entry it will only read later.
         *
         * @return the offset of the entry's first byte of data
         * @throws InvalidZipException as {@link #getData()} does before it returns a stream
         */
        long checkReadable() throws IOException {
            switch (compressionMethod) {
                case STORED:
                    break;
                case DEFLATED:
                    checkDeflatedSizes();
                    break;
                default:
                    throw new InvalidZipException("unsupported compression method " + compressionMethod
                            + " for entry [" + fileName + "]; only stored (0) and deflate (8) are supported");
            }
            return findStartOfData();
        }

        private void checkDeflatedSizes() throws IOException {
            // zip64 sizes are read as signed longs, so one at or above 2^63 arrives negative
            if (compressedSize < 0 || fileSize < 0) {
                throw new InvalidZipException("entry [" + fileName + "] declares a size out of range: compressed "
                        + Long.toUnsignedString(compressedSize) + ", uncompressed " + Long.toUnsignedString(fileSize));
            }
            long budget = Math.max(zipChannel.size(), DEFLATED_SIZE_BUDGET_FLOOR);
            if (fileSize > budget) {
                throw new InvalidZipException("deflated entry [" + fileName + "] declares an uncompressed size of "
                        + fileSize + " bytes, more than its budget of " + budget
                        + " bytes (the larger of the archive's length and " + DEFLATED_SIZE_BUDGET_FLOOR + " bytes)");
            }
        }

        /**
         * Reads {@code length} bytes of the archive starting at {@code startPosition}, ending early
         * only if the archive does.
         */
        private InputStream channelStream(final long startPosition, final long length) {
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
                    return offset >= length;
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
                    var lenToRead = (int)Math.min(len, length - offset); // cast is always valid because len is an int
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
        int compressionMethod = readUnsignedShort();
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

        return new Entry(fileName.array(), relativeOffsetOfLocalHeader, compressionMethod, compressedSize,
                uncompressedSize);
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

    /** Inflaters created by {@link Entry#getData()}, across every reader in this JVM. */
    private static final AtomicInteger INFLATERS_CREATED = new AtomicInteger();
    /** Inflaters created and not yet released by closing their stream. */
    private static final AtomicInteger OPEN_INFLATERS = new AtomicInteger();

    /**
     * How many inflaters deflated entries have created. An inflater holds native memory until it
     * is released, so the TDF reader's tests use this to check it creates them only when needed.
     */
    static int inflatersCreated() {
        return INFLATERS_CREATED.get();
    }

    /** How many inflaters are currently allocated: created, and their stream not yet closed. */
    static int openInflaters() {
        return OPEN_INFLATERS.get();
    }

    /**
     * Inflates a raw DEFLATE stream to exactly the uncompressed size the central directory
     * declares. Output is produced only as it is read, so a large entry is never held in memory,
     * and never past the declared size: once that many bytes have been returned the deflate
     * stream has to end there, and an entry that holds more, or ends sooner, is rejected. That
     * keeps a small entry from expanding without bound, whatever it claims about itself.
     * <p>
     * The CRC-32 is not checked. A TDF's integrity comes from its segment hashes and root
     * signature, which are verified over these bytes.
     */
    private static final class InflatingInputStream extends InputStream {
        private static final int INPUT_BUFFER_SIZE = 8192;

        private final InputStream compressed;
        private final long uncompressedSize;
        private final String entryName;
        private final Inflater inflater = new Inflater(true);
        private final byte[] input = new byte[INPUT_BUFFER_SIZE];
        private final byte[] singleByte = new byte[1];
        private long produced = 0;
        private boolean paddingFed = false;
        private boolean endVerified = false;
        private boolean closed = false;

        InflatingInputStream(InputStream compressed, long uncompressedSize, String entryName) {
            this.compressed = compressed;
            this.uncompressedSize = uncompressedSize;
            this.entryName = entryName;
            INFLATERS_CREATED.incrementAndGet();
            OPEN_INFLATERS.incrementAndGet();
        }

        @Override
        public int read() throws IOException {
            return read(singleByte, 0, 1) == -1 ? -1 : singleByte[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            Objects.checkFromIndexSize(off, len, b.length);
            if (closed) {
                throw new IOException("stream closed");
            }
            if (len == 0) {
                return 0;
            }
            if (produced == uncompressedSize) {
                verifyEnd();
                return -1;
            }
            // never ask for more than the declared size, so nothing past it reaches the caller
            int wanted = (int) Math.min(len, uncompressedSize - produced);
            while (true) {
                int n = inflate(b, off, wanted);
                if (n > 0) {
                    produced += n;
                    return n;
                }
                if (inflater.finished()) {
                    throw new InvalidZipException("deflated entry [" + entryName + "] ended after " + produced
                            + " bytes, but its declared uncompressed size is " + uncompressedSize);
                }
                fill();
            }
        }

        /**
         * At the declared size the deflate stream must also be at its end. Probes for a single
         * further byte: getting one means the entry holds more than it declares.
         */
        private void verifyEnd() throws IOException {
            if (endVerified) {
                return;
            }
            byte[] probe = new byte[1];
            while (!inflater.finished()) {
                if (inflate(probe, 0, 1) > 0) {
                    throw new InvalidZipException("deflated entry [" + entryName
                            + "] holds more data than its declared uncompressed size of " + uncompressedSize);
                }
                if (!inflater.finished()) {
                    fill();
                }
            }
            endVerified = true;
        }

        private int inflate(byte[] b, int off, int len) {
            int n;
            try {
                n = inflater.inflate(b, off, len);
            } catch (DataFormatException e) {
                throw new InvalidZipException("invalid deflate data in entry [" + entryName + "]", e);
            }
            if (n > 0 && paddingFed) {
                // the padding byte was taken as data, so the real compressed data ran out first
                throw truncated();
            }
            return n;
        }

        private void fill() throws IOException {
            if (inflater.needsDictionary()) {
                // raw deflate has no way to name a dictionary, so only corrupt data gets here
                throw new InvalidZipException("invalid deflate data in entry [" + entryName
                        + "]: it asks for a preset dictionary");
            }
            if (!inflater.needsInput()) {
                return;
            }
            int n = compressed.read(input, 0, input.length);
            if (n > 0) {
                inflater.setInput(input, 0, n);
                return;
            }
            if (!paddingFed) {
                // without the zlib wrapper, zlib may want one byte past the end of the deflate
                // stream before it reports the end (see Inflater(boolean)); ZipFile pads the same way
                paddingFed = true;
                input[0] = 0;
                inflater.setInput(input, 0, 1);
                return;
            }
            throw truncated();
        }

        private InvalidZipException truncated() {
            return new InvalidZipException("deflated entry [" + entryName + "] is truncated: its compressed data ran out after "
                    + produced + " of its declared " + uncompressedSize + " uncompressed bytes");
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                closed = true;
                inflater.end();
                OPEN_INFLATERS.decrementAndGet();
                compressed.close();
            }
        }
    }
}
