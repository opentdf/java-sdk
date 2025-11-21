package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.zip.CRC32;

/**
 * The ZipWriter class provides functionalities to create ZIP archive files.
 * It writes files and data to an underlying output stream in the ZIP file format.
 */
public class ZipWriter {

    private static final int ZIP_VERSION = 0x2D;
    private static final int ZIP_64_MAGIC_VAL = 0xFFFFFFFF;
    private static final long ZIP_64_END_OF_CD_RECORD_SIZE = 56;

    private static final int ZIP_64_GLOBAL_EXTENDED_INFO_EXTRA_FIELD_SIZE = 28;

    private static final int ZIP_64_DATA_DESCRIPTOR_SIZE = 24;
    private static final int HALF_SECOND = 2;
    private static final int BASE_YEAR = 1980;
    private static final int DEFAULT_SECOND_VALUE = 29;
    private static final int MONTH_SHIFT = 5;
    private final CountingOutputStream out;
    private final ArrayList<FileInfo> fileInfos = new ArrayList<>();

    public ZipWriter(OutputStream out) {
        this.out = new CountingOutputStream(out);
    }

    public OutputStream stream(String name) throws IOException {
        var startPosition = out.position;
        long fileTime, fileDate;
        fileTime = fileDate = getTimeDateUnMSDosFormat();

        var nameBytes = name.getBytes(StandardCharsets.UTF_8);
        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.setLastModifiedTime((int) fileTime);
        localFileHeader.setLastModifiedDate((int) fileDate);
        localFileHeader.setFilenameLength((short) nameBytes.length);
        localFileHeader.setCrc32(0);
        localFileHeader.setGeneralPurposeBitFlag((1 << 3) | (1 << 11)); // we are using the data descriptor and we are using UTF-8
        localFileHeader.setCompressedSize(ZIP_64_MAGIC_VAL);
        localFileHeader.setUncompressedSize(ZIP_64_MAGIC_VAL);
        localFileHeader.setExtraFieldLength((short) 0);

        localFileHeader.write(out, nameBytes);

        var crc = new CRC32();
        long fileStart = out.position;
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                crc.update(b);
                out.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                crc.update(b, off, len);
                out.write(b, off, len);
            }

            @Override
            public void close() throws IOException {
                super.close();

                long fileSize = out.position - fileStart;
                long crcValue = crc.getValue();

                // Write Zip64 data descriptor
                Zip64DataDescriptor dataDescriptor = new Zip64DataDescriptor();
                dataDescriptor.setCrc32(crcValue);
                dataDescriptor.setCompressedSize(fileSize);
                dataDescriptor.setUncompressedSize(fileSize);
                dataDescriptor.write(out);

                var fileInfo = new FileInfo();
                fileInfo.setOffset(startPosition);
                fileInfo.setFlag((short) localFileHeader.generalPurposeBitFlag);
                fileInfo.setSize(fileSize);
                fileInfo.setCrc(crcValue);
                fileInfo.setFilename(name);
                fileInfo.setFileTime((short) fileTime);
                fileInfo.setFileDate((short) fileDate);
                fileInfo.setIsZip64(true);

                fileInfos.add(fileInfo);
            }
        };
    }

    public void data(String name, byte[] content) throws IOException {
        fileInfos.add(writeByteArray(name, content, out));
    }

    /**
     * Writes the zip file to a stream and returns the number of
     * bytes written to the stream
     * @return the number of bytes written
     * @throws IOException when writing to the underlying stream causes an error
     */
    public long finish() throws IOException {
        final var startOfCentralDirectory = out.position;
        for (var fileInfo : fileInfos) {
            writeCentralDirectoryHeader(fileInfo, out);
        }
        final var sizeOfCentralDirectory = out.position - startOfCentralDirectory;
        final var hasZip64Entry = fileInfos.stream().anyMatch(f -> f.isZip64);
        writeEndOfCentralDirectory(hasZip64Entry, fileInfos.size(), startOfCentralDirectory, sizeOfCentralDirectory, out);

        return out.position;
    }

    private static void writeCentralDirectoryHeader(FileInfo fileInfo, OutputStream out) throws IOException {
        CDFileHeader cdFileHeader = new CDFileHeader();
        cdFileHeader.generalPurposeBitFlag = fileInfo.flag;
        cdFileHeader.lastModifiedTime = fileInfo.fileTime;
        cdFileHeader.lastModifiedDate = fileInfo.fileDate;
        cdFileHeader.crc32 = (int) fileInfo.crc;
        cdFileHeader.filenameLength = (short) fileInfo.filename.length();
        cdFileHeader.extraFieldLength = 0;
        cdFileHeader.compressedSize = (int) fileInfo.size;
        cdFileHeader.uncompressedSize = (int) fileInfo.size;
        cdFileHeader.localHeaderOffset = (int) fileInfo.offset;

        if (fileInfo.isZip64) {
            cdFileHeader.compressedSize = ZIP_64_MAGIC_VAL;
            cdFileHeader.uncompressedSize = ZIP_64_MAGIC_VAL;
            cdFileHeader.localHeaderOffset = ZIP_64_MAGIC_VAL;
            cdFileHeader.extraFieldLength = ZIP_64_GLOBAL_EXTENDED_INFO_EXTRA_FIELD_SIZE;
        }

        cdFileHeader.write(out, fileInfo.filename.getBytes(StandardCharsets.UTF_8));

        if (fileInfo.isZip64) {
            Zip64GlobalExtendedInfoExtraField zip64ExtendedInfoExtraField = new Zip64GlobalExtendedInfoExtraField();
            zip64ExtendedInfoExtraField.originalSize = fileInfo.size;
            zip64ExtendedInfoExtraField.compressedSize = fileInfo.size;
            zip64ExtendedInfoExtraField.localFileHeaderOffset = fileInfo.offset;
            zip64ExtendedInfoExtraField.write(out);
        }
    }

    private FileInfo writeByteArray(String name, byte[] data, CountingOutputStream out) throws IOException {
        var startPosition = out.position;
        long fileTime, fileDate;
        fileTime = fileDate = getTimeDateUnMSDosFormat();

        var crc = new CRC32();
        crc.update(data);
        var crcValue = crc.getValue();

        var nameBytes = name.getBytes(StandardCharsets.UTF_8);
        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.setLastModifiedTime((int) fileTime);
        localFileHeader.setLastModifiedDate((int) fileDate);
        localFileHeader.setFilenameLength((short) nameBytes.length);
        localFileHeader.setGeneralPurposeBitFlag(0);
        localFileHeader.setCrc32((int) crcValue);
        localFileHeader.setCompressedSize(data.length);
        localFileHeader.setUncompressedSize(data.length);
        localFileHeader.setExtraFieldLength((short) 0);

        localFileHeader.write(out, name.getBytes(StandardCharsets.UTF_8));

        out.write(data);

        var fileInfo = new FileInfo();
        fileInfo.offset = startPosition;
        fileInfo.flag = (1 << 11);
        fileInfo.size = data.length;
        fileInfo.crc = crcValue;
        fileInfo.filename = name;
        fileInfo.fileTime = (short) fileTime;
        fileInfo.fileDate = (short) fileDate;
        fileInfo.isZip64 = false;

        return fileInfo;
    }


    private void writeEndOfCentralDirectory(boolean hasZip64Entry, long numEntries, long startOfCentralDirectory, long sizeOfCentralDirectory, CountingOutputStream out) throws IOException {
        var isZip64 = hasZip64Entry
                || (numEntries & ~0xFF) != 0
                || (startOfCentralDirectory & ~0xFFFF) != 0
                || (sizeOfCentralDirectory & ~0xFFFF) != 0;

        if (isZip64) {
            var endPosition = out.position;
            writeZip64EndOfCentralDirectory(numEntries, startOfCentralDirectory, sizeOfCentralDirectory, out);
            writeZip64EndOfCentralDirectoryLocator(endPosition, out);
        }

        EndOfCDRecord endOfCDRecord = new EndOfCDRecord();
        endOfCDRecord.numberOfCDRecordEntries = isZip64 ? ZIP_64_MAGIC_VAL : (short) numEntries;
        endOfCDRecord.totalCDRecordEntries = isZip64 ? ZIP_64_MAGIC_VAL : (short) numEntries;
        endOfCDRecord.centralDirectoryOffset = isZip64 ? ZIP_64_MAGIC_VAL : (int) startOfCentralDirectory;
        endOfCDRecord.sizeOfCentralDirectory = isZip64 ? ZIP_64_MAGIC_VAL : (int) sizeOfCentralDirectory;

        endOfCDRecord.write(out);
    }

    private void writeZip64EndOfCentralDirectory(long numEntries, long startOfCentralDirectory, long sizeOfCentralDirectory, OutputStream out) throws IOException {
        Zip64EndOfCDRecord zip64EndOfCDRecord = new Zip64EndOfCDRecord();
        zip64EndOfCDRecord.numberOfCDRecordEntries = numEntries;
        zip64EndOfCDRecord.totalCDRecordEntries = numEntries;
        zip64EndOfCDRecord.centralDirectorySize = sizeOfCentralDirectory;
        zip64EndOfCDRecord.startingDiskCentralDirectoryOffset = startOfCentralDirectory;

        zip64EndOfCDRecord.write(out);
    }

    private void writeZip64EndOfCentralDirectoryLocator(long startOfEndOfCD, OutputStream out) throws IOException {
        Zip64EndOfCDRecordLocator zip64EndOfCDRecordLocator = new Zip64EndOfCDRecordLocator();
        zip64EndOfCDRecordLocator.setCDOffset(startOfEndOfCD);
        zip64EndOfCDRecordLocator.write(out);
    }

    private static class CountingOutputStream extends OutputStream {

        private final OutputStream inner;
        private long position;

        public CountingOutputStream(OutputStream inner) {
            this.inner = inner;
            this.position = 0;
        }

        @Override
        public void write(int b) throws IOException {
            inner.write(b);
            position += 1;
        }

        @Override
        public void write(byte[] b) throws IOException {
            inner.write(b);
            position += b.length;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            inner.write(b, off, len);
            position += len;
        }
    }

    private static long getTimeDateUnMSDosFormat() {
        LocalDateTime now = LocalDateTime.now();
        int timeInDos = now.getHour() << 11 | now.getMinute() << 5 | Math.max(now.getSecond() / HALF_SECOND, DEFAULT_SECOND_VALUE);
        int dateInDos = (now.getYear() - BASE_YEAR) << 9 | ((now.getMonthValue() + 1) << MONTH_SHIFT) | now.getDayOfMonth();
        return ((long) timeInDos << 16) | dateInDos;
    }

    private static class LocalFileHeader {
        private static final int signature = 0x04034b50;
        private static final int version = ZIP_VERSION;
        private int generalPurposeBitFlag;
        private static final int compressionMethod = 0;
        private int lastModifiedTime;
        private int lastModifiedDate;
        private int crc32;
        private int compressedSize;
        private int uncompressedSize;

        private short filenameLength;
        private short extraFieldLength = 0;

        public void setGeneralPurposeBitFlag(int generalPurposeBitFlag) {
            this.generalPurposeBitFlag = generalPurposeBitFlag;
        }

        public int getGeneralPurposeBitFlag() {
            return generalPurposeBitFlag;
        }

        public short getFilenameLength() {
            return filenameLength;
        }

        public void setFilenameLength(short filenameLength) {
            this.filenameLength = filenameLength;
        }

        public short getExtraFieldLength() {
            return extraFieldLength;
        }

        public void setExtraFieldLength(short extraFieldLength) {
            this.extraFieldLength = extraFieldLength;
        }

        public void setLastModifiedTime(int lastModifiedTime) {
            this.lastModifiedTime = lastModifiedTime;
        }

        public int getLastModifiedTime() {
            return lastModifiedTime;
        }

        public void setLastModifiedDate(int lastModifiedDate) {
            this.lastModifiedDate = lastModifiedDate;
        }

        public int getLastModifiedDate() {
            return lastModifiedDate;
        }

        public void setCrc32(int crc32) {
            this.crc32 = crc32;
        }

        public int getCrc32() {
            return crc32;
        }

        public int getCompressionMethod() {
            return compressionMethod;
        }

        public void setCompressedSize(int compressedSize) {
            this.compressedSize = compressedSize;
        }

        public int getCompressedSize() {
            return compressedSize;
        }

        public void setUncompressedSize(int uncompressedSize) {
            this.uncompressedSize = uncompressedSize;
        }

        public int getUncompressedSize() {
            return uncompressedSize;
        }


        void write(OutputStream out, byte[] filename) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(30 + filename.length);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putShort((short) version);
            buffer.putShort((short) generalPurposeBitFlag);
            buffer.putShort((short) compressionMethod);
            buffer.putShort((short) lastModifiedTime);
            buffer.putShort((short) lastModifiedDate);
            buffer.putInt(crc32);
            buffer.putInt(compressedSize);
            buffer.putInt(uncompressedSize);
            buffer.putShort(filenameLength);
            buffer.putShort(extraFieldLength);
            buffer.put(filename);

            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class Zip64DataDescriptor {
        private final int signature = 0x08074b50;
        private long crc32;
        private long compressedSize;
        private long uncompressedSize;

        public int getSignature() {
            return signature;
        }

        public long getCrc32() {
            return crc32;
        }

        public void setCrc32(long crc32) {
            this.crc32 = crc32;
        }

        public long getCompressedSize() {
            return compressedSize;
        }

        public void setCompressedSize(long compressedSize) {
            this.compressedSize = compressedSize;
        }

        public long getUncompressedSize() {
            return uncompressedSize;
        }

        public void setUncompressedSize(long uncompressedSize) {
            this.uncompressedSize = uncompressedSize;
        }

        void write(OutputStream out) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(ZIP_64_DATA_DESCRIPTOR_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putInt((int) crc32);
            buffer.putLong(compressedSize);
            buffer.putLong(uncompressedSize);

            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class CDFileHeader {
        private final int signature = 0x02014b50;
        private final short versionCreated = ZIP_VERSION;
        private final short versionNeeded = ZIP_VERSION;
        private int generalPurposeBitFlag;
        private final int compressionMethod = 0;
        private int lastModifiedTime;
        private int lastModifiedDate;
        private int crc32;
        private int compressedSize;
        private int uncompressedSize;
        private short filenameLength;
        private short extraFieldLength;
        private final short fileCommentLength = 0;
        private final short diskNumberStart = 0;
        private final short internalFileAttributes = 0;
        private final int externalFileAttributes = 0;
        private int localHeaderOffset;

        public int getSignature() {
            return signature;
        }

        public short getVersionCreated() {
            return versionCreated;
        }

        public short getVersionNeeded() {
            return versionNeeded;
        }

        public int getGeneralPurposeBitFlag() {
            return generalPurposeBitFlag;
        }

        public void setGeneralPurposeBitFlag(int generalPurposeBitFlag) {
            this.generalPurposeBitFlag = generalPurposeBitFlag;
        }

        public int getCompressionMethod() {
            return compressionMethod;
        }

        public int getLastModifiedTime() {
            return lastModifiedTime;
        }

        public void setLastModifiedTime(int lastModifiedTime) {
            this.lastModifiedTime = lastModifiedTime;
        }

        public int getLastModifiedDate() {
            return lastModifiedDate;
        }

        public void setLastModifiedDate(int lastModifiedDate) {
            this.lastModifiedDate = lastModifiedDate;
        }

        public int getCrc32() {
            return crc32;
        }

        public void setCrc32(int crc32) {
            this.crc32 = crc32;
        }

        public int getCompressedSize() {
            return compressedSize;
        }

        public void setCompressedSize(int compressedSize) {
            this.compressedSize = compressedSize;
        }

        public int getUncompressedSize() {
            return uncompressedSize;
        }

        public void setUncompressedSize(int uncompressedSize) {
            this.uncompressedSize = uncompressedSize;
        }

        public short getFilenameLength() {
            return filenameLength;
        }

        public void setFilenameLength(short filenameLength) {
            this.filenameLength = filenameLength;
        }

        public short getExtraFieldLength() {
            return extraFieldLength;
        }

        public void setExtraFieldLength(short extraFieldLength) {
            this.extraFieldLength = extraFieldLength;
        }

        public short getFileCommentLength() {
            return fileCommentLength;
        }

        public short getDiskNumberStart() {
            return diskNumberStart;
        }

        public short getInternalFileAttributes() {
            return internalFileAttributes;
        }

        public int getExternalFileAttributes() {
            return externalFileAttributes;
        }

        public int getLocalHeaderOffset() {
            return localHeaderOffset;
        }

        public void setLocalHeaderOffset(int localHeaderOffset) {
            this.localHeaderOffset = localHeaderOffset;
        }

        void write(OutputStream out, byte[] filename) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(46 + filename.length);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putShort(versionCreated);
            buffer.putShort(versionNeeded);
            buffer.putShort((short) generalPurposeBitFlag);
            buffer.putShort((short) compressionMethod);
            buffer.putShort((short) lastModifiedTime);
            buffer.putShort((short) lastModifiedDate);
            buffer.putInt(crc32);
            buffer.putInt(compressedSize);
            buffer.putInt(uncompressedSize);
            buffer.putShort((short) filename.length);
            buffer.putShort(extraFieldLength);
            buffer.putShort(fileCommentLength);
            buffer.putShort(diskNumberStart);
            buffer.putShort(internalFileAttributes);
            buffer.putInt(externalFileAttributes);
            buffer.putInt(localHeaderOffset);
            buffer.put(filename);

            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class Zip64GlobalExtendedInfoExtraField {
        private final short signature = 0x0001;
        private final short size = ZIP_64_GLOBAL_EXTENDED_INFO_EXTRA_FIELD_SIZE - 4;
        private long originalSize;
        private long compressedSize;
        private long localFileHeaderOffset;

        public long getLocalFileHeaderOffset() {
            return localFileHeaderOffset;
        }

        public void setLocalFileHeaderOffset(long localFileHeaderOffset) {
            this.localFileHeaderOffset = localFileHeaderOffset;
        }

        public long getCompressedSize() {
            return compressedSize;
        }

        public void setCompressedSize(long compressedSize) {
            this.compressedSize = compressedSize;
        }

        public long getOriginalSize() {
            return originalSize;
        }

        public void setOriginalSize(long originalSize) {
            this.originalSize = originalSize;
        }

        public short getSize() {
            return size;
        }

        public short getSignature() {
            return signature;
        }

        void write(OutputStream out) throws IOException {
            var buffer = ByteBuffer.allocate(ZIP_64_GLOBAL_EXTENDED_INFO_EXTRA_FIELD_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putShort(signature);
            buffer.putShort(size);
            buffer.putLong(compressedSize);
            buffer.putLong(originalSize);
            buffer.putLong(localFileHeaderOffset);

            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class EndOfCDRecord {
        private final int signature = 0x06054b50;
        private final short diskNumber = 0;
        private final short startDiskNumber = 0;
        private short numberOfCDRecordEntries;
        private short totalCDRecordEntries;
        private int sizeOfCentralDirectory;
        private int centralDirectoryOffset;
        private final short commentLength = 0;

        public int getSignature() {
            return signature;
        }

        public short getDiskNumber() {
            return diskNumber;
        }

        public short getStartDiskNumber() {
            return startDiskNumber;
        }

        public short getNumberOfCDRecordEntries() {
            return numberOfCDRecordEntries;
        }

        public void setNumberOfCDRecordEntries(short numberOfCDRecordEntries) {
            this.numberOfCDRecordEntries = numberOfCDRecordEntries;
        }

        public short getTotalCDRecordEntries() {
            return totalCDRecordEntries;
        }

        public void setTotalCDRecordEntries(short totalCDRecordEntries) {
            this.totalCDRecordEntries = totalCDRecordEntries;
        }

        public int getSizeOfCentralDirectory() {
            return sizeOfCentralDirectory;
        }

        public void setSizeOfCentralDirectory(int sizeOfCentralDirectory) {
            this.sizeOfCentralDirectory = sizeOfCentralDirectory;
        }

        public int getCentralDirectoryOffset() {
            return centralDirectoryOffset;
        }

        public void setCentralDirectoryOffset(int centralDirectoryOffset) {
            this.centralDirectoryOffset = centralDirectoryOffset;
        }

        public short getCommentLength() {
            return commentLength;
        }

        void write(OutputStream out) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(22);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putShort(diskNumber);
            buffer.putShort(startDiskNumber);
            buffer.putShort(numberOfCDRecordEntries);
            buffer.putShort(totalCDRecordEntries);
            buffer.putInt(sizeOfCentralDirectory);
            buffer.putInt(centralDirectoryOffset);
            buffer.putShort(commentLength);

            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class Zip64EndOfCDRecord {
        private final int signature = 0x06064b50;
        private final long recordSize = ZIP_64_END_OF_CD_RECORD_SIZE - 12;
        private final short versionMadeBy = ZIP_VERSION;
        private final short versionToExtract = ZIP_VERSION;
        private final int diskNumber = 0;
        private final int startDiskNumber = 0;
        private long numberOfCDRecordEntries;
        private long totalCDRecordEntries;
        private long centralDirectorySize;
        private long startingDiskCentralDirectoryOffset;

        public int getSignature() {
            return signature;
        }

        public long getRecordSize() {
            return recordSize;
        }

        public short getVersionMadeBy() {
            return versionMadeBy;
        }

        public short getVersionToExtract() {
            return versionToExtract;
        }

        public int getDiskNumber() {
            return diskNumber;
        }

        public int getStartDiskNumber() {
            return startDiskNumber;
        }

        public long getNumberOfCDRecordEntries() {
            return numberOfCDRecordEntries;
        }

        public void setNumberOfCDRecordEntries(long numberOfCDRecordEntries) {
            this.numberOfCDRecordEntries = numberOfCDRecordEntries;
        }

        public long getTotalCDRecordEntries() {
            return totalCDRecordEntries;
        }

        public void setTotalCDRecordEntries(long totalCDRecordEntries) {
            this.totalCDRecordEntries = totalCDRecordEntries;
        }

        public long getCentralDirectorySize() {
            return centralDirectorySize;
        }

        public void setCentralDirectorySize(long centralDirectorySize) {
            this.centralDirectorySize = centralDirectorySize;
        }

        public long getStartingDiskCentralDirectoryOffset() {
            return startingDiskCentralDirectoryOffset;
        }

        public void setStartingDiskCentralDirectoryOffset(long startingDiskCentralDirectoryOffset) {
            this.startingDiskCentralDirectoryOffset = startingDiskCentralDirectoryOffset;
        }

        void write(OutputStream out) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(56);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putLong(recordSize);
            buffer.putShort(versionMadeBy);
            buffer.putShort(versionToExtract);
            buffer.putInt(diskNumber);
            buffer.putInt(startDiskNumber);
            buffer.putLong(numberOfCDRecordEntries);
            buffer.putLong(totalCDRecordEntries);
            buffer.putLong(centralDirectorySize);
            buffer.putLong(startingDiskCentralDirectoryOffset);

            out.write(buffer.array());
        }
    }


    private static class Zip64EndOfCDRecordLocator {
        private static final int signature = 0x07064b50;
        private static final int CDStartDiskNumber = 0;
        private long CDOffset;
        private static final int numberOfDisks = 1;

        long getCDOffset() {
            return CDOffset;
        }

        void setCDOffset(long CDOffset) {
            this.CDOffset = CDOffset;
        }

        void write(OutputStream out) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(20);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putInt(CDStartDiskNumber);
            buffer.putLong(CDOffset);
            buffer.putInt(numberOfDisks);
            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class FileInfo {
        private long crc;
        private long size;
        private long offset;
        private String filename;
        private short fileTime;
        private short fileDate;
        private short flag;
        private boolean isZip64;

        long getCrc() {
            return crc;
        }

        void setCrc(long crc) {
            this.crc = crc;
        }

        long getSize() {
            return size;
        }

        public void setSize(long size) {
            this.size = size;
        }

        public long getOffset() {
            return offset;
        }

        public void setOffset(long offset) {
            this.offset = offset;
        }

        public String getFilename() {
            return filename;
        }

        public void setFilename(String filename) {
            this.filename = filename;
        }

        public short getFileTime() {
            return fileTime;
        }

        public void setFileTime(short fileTime) {
            this.fileTime = fileTime;
        }

        public short getFileDate() {
            return fileDate;
        }

        public void setFileDate(short fileDate) {
            this.fileDate = fileDate;
        }

        public short getFlag() {
            return flag;
        }

        public void setFlag(short flag) {
            this.flag = flag;
        }

        public boolean isZip64() {
            return isZip64;
        }

        public void setIsZip64(boolean zip64) {
            isZip64 = zip64;
        }
    }
}