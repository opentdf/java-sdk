package io.opentdf.platform.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.zip.CRC32;

public class ZipWriter {

    private static final int ZIP_VERSION = 0x2D;
    private static final int ZIP_64_MAGIC_VAL = 0xFFFFFFFF;
    private static final long ZIP_64_END_OF_CD_RECORD_SIZE = 56;
    private static final int ZIP_64_LOCAL_EXTENDED_INFO_EXTRA_FIELD_SIZE = 24;

    private static final int ZIP_64_GLOBAL_EXTENDED_INFO_EXTRA_FIELD_SIZE = 28;
    private static final int ZIP_32_DATA_DESCRIPTOR_SIZE = 16;

    private static final int ZIP_64_DATA_DESCRIPTOR_SIZE = 24;
    private static final int HALF_SECOND = 2;
    private static final int BASE_YEAR = 1980;
    private static final int DEFAULT_SECOND_VALUE = 29;
    private static final int MONTH_SHIFT = 5;
    private static class FileBytes {
        public FileBytes(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }

        final String name;
        final byte[] data;
    }

    private static class InputStream {
        public InputStream(String name, java.io.InputStream data) {
            this.name = name;
            this.data = data;
        }

        final String name;
        private final java.io.InputStream data;
    }

    private final ArrayList<FileBytes> byteFiles = new ArrayList<>();
    private final ArrayList<InputStream> streamFiles = new ArrayList<>();

    public ZipWriter file(String name, java.io.InputStream data) {
        streamFiles.add(new InputStream(name, data));
        return this;
    }

    public ZipWriter file(String name, byte[] content) {
        byteFiles.add(new FileBytes(name, content));
        return this;
    }

    /**
     * Writes the zip file to a stream and returns the number of
     * bytes written to the stream
     * @param sink
     * @return
     * @throws IOException
     */
    public long build(OutputStream sink) throws IOException {
        var out = new CountingOutputStream(sink);
        ArrayList<FileInfo> fileInfos = new ArrayList<>();

        for (var byteFile : byteFiles) {
            var fileInfo = writeByteArray(byteFile.name, byteFile.data, out);
            fileInfos.add(fileInfo);
        }

        for (var streamFile : streamFiles) {
            var fileInfo = writeStream(streamFile.name, streamFile.data, out);
            fileInfos.add(fileInfo);
        }

        final var startOfCentralDirectory = out.position;
        for (var fileInfo : fileInfos) {
            writeCentralDirectoryHeader(fileInfo, out);
        }

        final var sizeOfCentralDirectory = out.position - startOfCentralDirectory;
        writeEndOfCentralDirectory(!streamFiles.isEmpty(), fileInfos.size(), startOfCentralDirectory, sizeOfCentralDirectory, out);

        return out.position;
    }

    public byte[] build() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        build(out);
        return out.toByteArray();
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

    private FileInfo writeStream(String name, java.io.InputStream data, CountingOutputStream out) throws IOException {
        var startPosition = out.position;
        long fileTime, fileDate;
        fileTime = fileDate = getTimeDateUnMSDosFormat();

        var nameBytes = name.getBytes(StandardCharsets.UTF_8);
        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.lastModifiedTime = (int) fileTime;
        localFileHeader.lastModifiedDate = (int) fileDate;
        localFileHeader.filenameLength = (short) nameBytes.length;
        localFileHeader.crc32 = 0;
        localFileHeader.generalPurposeBitFlag = (1 << 3) | (1 << 11); // we are using the data descriptor and we are using UTF-8
        localFileHeader.compressedSize = ZIP_64_MAGIC_VAL;
        localFileHeader.uncompressedSize = ZIP_64_MAGIC_VAL;
        localFileHeader.extraFieldLength = 0;

        localFileHeader.write(out, nameBytes);

        var crc = new CRC32();
        var outputStream = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                crc.update(b);
                out.write(b);
            }

            @Override
            public void write(byte[] b) throws IOException {
                crc.update(b);
                out.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                crc.update(b, off, len);
                out.write(b, off, len);
            }
        };

        long fileStart = out.position;
        data.transferTo(outputStream);
        long fileSize = out.position - fileStart;
        long crcValue = crc.getValue();

        // Write Zip64 data descriptor
        Zip64DataDescriptor dataDescriptor = new Zip64DataDescriptor();
        dataDescriptor.crc32 = crcValue;
        dataDescriptor.compressedSize = fileSize;
        dataDescriptor.uncompressedSize = fileSize;
        dataDescriptor.write(out);

        var fileInfo = new FileInfo();
        fileInfo.offset = startPosition;
        fileInfo.flag = (short) localFileHeader.generalPurposeBitFlag;
        fileInfo.size = fileSize;
        fileInfo.crc = crcValue;
        fileInfo.filename = name;
        fileInfo.fileTime = (short) fileTime;
        fileInfo.fileDate = (short) fileDate;
        fileInfo.isZip64 = true;

        return fileInfo;
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
        localFileHeader.lastModifiedTime = (int) fileTime;
        localFileHeader.lastModifiedDate = (int) fileDate;
        localFileHeader.filenameLength = (short) nameBytes.length;
        localFileHeader.generalPurposeBitFlag = 0;
        localFileHeader.crc32 = (int) crcValue;
        localFileHeader.compressedSize = data.length;
        localFileHeader.uncompressedSize = data.length;
        localFileHeader.extraFieldLength = 0;

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
        zip64EndOfCDRecordLocator.CDOffset = startOfEndOfCD;

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
        final int signature = 0x04034b50;
        final int version = ZIP_VERSION;
        int generalPurposeBitFlag;
        final int compressionMethod = 0;
        int lastModifiedTime;
        int lastModifiedDate;
        int crc32;
        int compressedSize;
        int uncompressedSize;

        short filenameLength;
        short extraFieldLength = 0;

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
        final int signature = 0x08074b50;
        long crc32;
        long compressedSize;
        long uncompressedSize;

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

    private static class Zip32DataDescriptor {
        final int signature = 0x08074b50;
        ;
        long crc32;
        int compressedSize;
        int uncompressedSize;

        void write(OutputStream out) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(ZIP_32_DATA_DESCRIPTOR_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putInt((int) crc32);
            buffer.putInt(compressedSize);
            buffer.putInt(uncompressedSize);
            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class CDFileHeader {
        final int signature = 0x02014b50;
        final short versionCreated = ZIP_VERSION;
        final short versionNeeded = ZIP_VERSION;
        int generalPurposeBitFlag;
        final int compressionMethod = 0;
        int lastModifiedTime;
        int lastModifiedDate;
        int crc32;
        int compressedSize;
        int uncompressedSize;
        short filenameLength;
        short extraFieldLength;
        final short fileCommentLength = 0;
        final short diskNumberStart = 0;
        final short internalFileAttributes = 0;
        final int externalFileAttributes = 0;
        int localHeaderOffset;

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

    private static class Zip64LocalExtendedInfoExtraField {
        final short signature = 0x0001;
        final short size = ZIP_64_LOCAL_EXTENDED_INFO_EXTRA_FIELD_SIZE;
        long originalSize;
        long compressedSize;

        void write(OutputStream out) throws IOException {
            var buffer = ByteBuffer.allocate(ZIP_64_LOCAL_EXTENDED_INFO_EXTRA_FIELD_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putShort(signature);
            buffer.putShort(size);
            buffer.putLong(originalSize);
            buffer.putLong(compressedSize);

            out.write(buffer.array());
            assert buffer.position() == buffer.capacity();
        }
    }

    private static class Zip64GlobalExtendedInfoExtraField {
        final short signature = 0x0001;
        final short size = ZIP_64_GLOBAL_EXTENDED_INFO_EXTRA_FIELD_SIZE - 4;
        long originalSize;
        long compressedSize;
        long localFileHeaderOffset;

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
        final int signature = 0x06054b50;
        final short diskNumber = 0;
        final short startDiskNumber = 0;
        short numberOfCDRecordEntries;
        short totalCDRecordEntries;
        int sizeOfCentralDirectory;
        int centralDirectoryOffset;
        final short commentLength = 0;

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
        final int signature = 0x06064b50;
        final long recordSize = ZIP_64_END_OF_CD_RECORD_SIZE - 12;
        final short versionMadeBy = ZIP_VERSION;
        final short versionToExtract = ZIP_VERSION;
        final int diskNumber = 0;
        final int startDiskNumber = 0;
        long numberOfCDRecordEntries;
        long totalCDRecordEntries;
        long centralDirectorySize;
        long startingDiskCentralDirectoryOffset;

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
        final int signature = 0x07064b50;
        final int CDStartDiskNumber = 0;
        long CDOffset;
        final int numberOfDisks = 1;

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
        long crc;
        long size;
        long offset;
        String filename;
        short fileTime;
        short fileDate;
        short flag;
        boolean isZip64;
    }
}