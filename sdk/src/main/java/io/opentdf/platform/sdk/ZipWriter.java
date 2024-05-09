package io.opentdf.platform.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.zip.CRC32;

public class ZipWriter {

    private static final int ZIP_VERSION = 20;
    private static final int ZIP_64_MAGIC_VAL = 0xFFFFFFFF;
    private static final int ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE = 24;
    private static final int ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE = 28;
    private static final int ZIP_32_DATA_DESCRIPTOR_SIZE = 16;
    private static final int HALF_SECOND = 2;
    private static final int BASE_YEAR = 1980;
    private static final int DEFAULT_SECOND_VALUE = 29;
    private static final int MONTH_SHIFT = 5;

    public static class Builder {
        private boolean isZip64;

        private static class FileBytes {
            public FileBytes(String name, byte[] data) {
                this.name = name;
                this.data = data;
            }

            final String name;
            final byte[] data;
        }

        private static class FileStream {
            public FileStream(String name, InputStream data) {
                this.name = name;
                this.data = data;
            }

            final String name;
            private final InputStream data;
        }

        private final ArrayList<FileBytes> byteFiles = new ArrayList<>();
        private final ArrayList<FileStream> streamFiles = new ArrayList<>();

        public Builder file(String name, InputStream data) {
            streamFiles.add(new FileStream(name, data));
            return this;
        }

        public Builder file(String name, byte[] content){
            byteFiles.add(new FileBytes(name, content));
            return this;
        }

        public Builder zip64(boolean isZip64) {
            this.isZip64 = isZip64;
            return this;
        }

        public void build(OutputStream sink) throws IOException {
            var out = new CountingOutputStream(sink);
            ArrayList<FileInfo> fileInfos = new ArrayList<>();

            for (var byteFile: byteFiles) {
                var fileInfo = writeFile(byteFile.name, byteFile.data, out);
                fileInfos.add(fileInfo);
            }

            final var startOfCentralDirectory = out.position;
            for (var fileInfo: fileInfos) {
                writeCentralDirectoryHeader(fileInfo, this.isZip64, out);
            }
            final var sizeOfCentralDirectory = out.position - startOfCentralDirectory;
            writeEndOfCentralDirectory((short)fileInfos.size(), (int)startOfCentralDirectory, (int)sizeOfCentralDirectory, out);
        }

        private static void writeCentralDirectoryHeader(FileInfo fileInfo, boolean isZip64, OutputStream out) throws IOException {
            CDFileHeader cdFileHeader = new CDFileHeader();
            cdFileHeader.generalPurposeBitFlag = fileInfo.flag;
            cdFileHeader.compressionMethod = 0;
            cdFileHeader.lastModifiedTime = fileInfo.fileTime;
            cdFileHeader.lastModifiedDate = fileInfo.fileDate;
            cdFileHeader.crc32 = (int) fileInfo.crc;
            cdFileHeader.filenameLength = (short) fileInfo.filename.length();
            cdFileHeader.extraFieldLength = 0;
            cdFileHeader.compressedSize = (int) fileInfo.size;
            cdFileHeader.uncompressedSize = (int) fileInfo.size;
            cdFileHeader.localHeaderOffset = (int) fileInfo.offset;

            if (isZip64) {
                cdFileHeader.compressedSize = ZIP_64_MAGIC_VAL;
                cdFileHeader.uncompressedSize = ZIP_64_MAGIC_VAL;
                cdFileHeader.localHeaderOffset = ZIP_64_MAGIC_VAL;
                cdFileHeader.extraFieldLength = ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE;
            }

            cdFileHeader.write(out, fileInfo.filename.getBytes(StandardCharsets.UTF_8));

            if (isZip64) {
                Zip64ExtendedInfoExtraField zip64ExtendedInfoExtraField = new Zip64ExtendedInfoExtraField();
                zip64ExtendedInfoExtraField.originalSize = fileInfo.size;
                zip64ExtendedInfoExtraField.compressedSize = fileInfo.size;
                zip64ExtendedInfoExtraField.localFileHeaderOffset = fileInfo.offset;

                zip64ExtendedInfoExtraField.write(out);
            }
        }


        private FileInfo writeFile(String name, byte[] data, CountingOutputStream out) throws IOException {
            var startPosition = out.position;
            long fileTime, fileDate;
            fileTime = fileDate = getTimeDateUnMSDosFormat();

            var nameBytes = name.getBytes(StandardCharsets.UTF_8);
            LocalFileHeader localFileHeader = new LocalFileHeader();
            localFileHeader.lastModifiedTime = (int) fileTime;
            localFileHeader.lastModifiedDate = (int) fileDate;
            localFileHeader.filenameLength = (short) nameBytes.length;
            localFileHeader.crc32 = 0;
            localFileHeader.compressedSize = 0;
            localFileHeader.uncompressedSize = 0;
            localFileHeader.extraFieldLength = 0;

            if (this.isZip64) {
                localFileHeader.compressedSize = ZIP_64_MAGIC_VAL;
                localFileHeader.uncompressedSize = ZIP_64_MAGIC_VAL;
                localFileHeader.extraFieldLength = ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE;

            }

            localFileHeader.write(out, nameBytes);
            if (this.isZip64) {
                Zip64ExtendedLocalInfoExtraField zip64ExtendedLocalInfoExtraField = new Zip64ExtendedLocalInfoExtraField();
                zip64ExtendedLocalInfoExtraField.originalSize = data.length;
                zip64ExtendedLocalInfoExtraField.compressedSize = data.length;
                zip64ExtendedLocalInfoExtraField.write(out);
            }

            out.write(data);

            var crc = new CRC32();
            crc.update(data);
            var crcValue = crc.getValue();

            if (this.isZip64) {
                // Write Zip64 data descriptor
                Zip64DataDescriptor zip64DataDescriptor = new Zip64DataDescriptor();
                zip64DataDescriptor.crc32 = crcValue;
                zip64DataDescriptor.compressedSize = data.length;
                zip64DataDescriptor.uncompressedSize = data.length;

                zip64DataDescriptor.write(out);
            } else {
                // Write Zip32 data descriptor
                Zip32DataDescriptor zip32DataDescriptor = new Zip32DataDescriptor();
                zip32DataDescriptor.crc32 = crcValue;
                zip32DataDescriptor.compressedSize = data.length;
                zip32DataDescriptor.uncompressedSize = data.length;

                zip32DataDescriptor.write(out);
            }

            var fileInfo = new FileInfo();
            fileInfo.offset = startPosition;
            fileInfo.flag = 0x8;
            fileInfo.size = data.length;
            fileInfo.crc = crcValue;
            fileInfo.filename = name;
            fileInfo.fileTime = (short)fileTime;
            fileInfo.fileDate = (short)fileDate;

            return fileInfo;
        }


        private void writeEndOfCentralDirectory(short numEntries, int startOfCentralDirectory, int sizeOfCentralDirectory, OutputStream out) throws IOException {
            if (this.isZip64) {
                writeZip64EndOfCentralDirectory(numEntries, startOfCentralDirectory, sizeOfCentralDirectory, out);
                writeZip64EndOfCentralDirectoryLocator(startOfCentralDirectory, out);
            }

            EndOfCDRecord endOfCDRecord = new EndOfCDRecord();
            endOfCDRecord.numberOfCDRecordEntries = numEntries;
            endOfCDRecord.totalCDRecordEntries = numEntries;
            endOfCDRecord.centralDirectoryOffset = startOfCentralDirectory;
            endOfCDRecord.sizeOfCentralDirectory = sizeOfCentralDirectory;

            endOfCDRecord.write(out);
        }

        private void writeZip64EndOfCentralDirectory(short numEntries, int startOfCentralDirectory, int sizeOfCentralDirectory, OutputStream out) throws IOException {
            Zip64EndOfCDRecord zip64EndOfCDRecord = new Zip64EndOfCDRecord();
            zip64EndOfCDRecord.diskNumber = 0;
            zip64EndOfCDRecord.startDiskNumber = 0;
            zip64EndOfCDRecord.numberOfCDRecordEntries = numEntries;
            zip64EndOfCDRecord.totalCDRecordEntries = numEntries;
            zip64EndOfCDRecord.centralDirectorySize = sizeOfCentralDirectory;
            zip64EndOfCDRecord.startingDiskCentralDirectoryOffset = startOfCentralDirectory;

            zip64EndOfCDRecord.write(out);
        }

        private void writeZip64EndOfCentralDirectoryLocator(long startOfCentralDirectory, OutputStream out) throws IOException {
            Zip64EndOfCDRecordLocator zip64EndOfCDRecordLocator = new Zip64EndOfCDRecordLocator();
            zip64EndOfCDRecordLocator.CDOffset = startOfCentralDirectory;

            zip64EndOfCDRecordLocator.write(out);
        }
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
        final int generalPurposeBitFlag = 0x08;
        final int compressionMethod = 0;
        int lastModifiedTime;
        int lastModifiedDate;
        int crc32;
        int compressedSize;
        int uncompressedSize;
        short filenameLength;
        short extraFieldLength;

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
        }
    }

    private static class Zip64ExtendedLocalInfoExtraField {
        final short signature = 0x0001;
        final short size = ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE - 4;
        long originalSize;
        long compressedSize;

        void write(OutputStream out) throws IOException {
            var buffer = ByteBuffer.allocate(ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putShort(signature);
            buffer.putShort(size);
            buffer.putLong(originalSize);
            buffer.putLong(compressedSize);

            out.write(buffer.array());
        }
    }

    private static class Zip64DataDescriptor {
        final int signature = 0x08074b50;
        long crc32;
        long compressedSize;
        long uncompressedSize;

        void write(OutputStream out) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(ZIP_32_DATA_DESCRIPTOR_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putInt((int)crc32);
            buffer.putInt((int)compressedSize);
            buffer.putInt((int)uncompressedSize);

            out.write(buffer.array());
        }
    }

    private static class Zip32DataDescriptor {
        final int signature = 0x08074b50;;
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
        }
    }

    private static class CDFileHeader {
        final int signature = 0x02014b50;
        final int versionCreated = ZIP_VERSION;
        final int versionNeeded = ZIP_VERSION;
        int generalPurposeBitFlag;
        int compressionMethod;
        int lastModifiedTime;
        int lastModifiedDate;
        int crc32;
        int compressedSize;
        int uncompressedSize;
        short filenameLength;
        short extraFieldLength = 0;
        final short fileCommentLength = 0;
        final short diskNumberStart = 0;
        final short internalFileAttributes = 0;
        final int externalFileAttributes = 0;
        int localHeaderOffset;

        void write(OutputStream out, byte[] filename) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(46 + filename.length);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(signature);
            buffer.putShort((short) versionCreated);
            buffer.putShort((short) versionNeeded);
            buffer.putShort((short) generalPurposeBitFlag);
            buffer.putShort((short) compressionMethod);
            buffer.putShort((short) lastModifiedTime);
            buffer.putShort((short) lastModifiedDate);
            buffer.putInt(crc32);
            buffer.putInt(compressedSize);
            buffer.putInt(uncompressedSize);
            buffer.putShort(filenameLength);
            buffer.putShort(extraFieldLength);
            buffer.putShort(fileCommentLength);
            buffer.putShort(diskNumberStart);
            buffer.putShort(internalFileAttributes);
            buffer.putInt(externalFileAttributes);
            buffer.putInt(localHeaderOffset);
            buffer.put(filename);

            out.write(buffer.array());
        }
    }

    private static class Zip64ExtendedInfoExtraField {
        final short signature = 0x0001;
        final short size = 0x0001;
        long originalSize;
        long compressedSize;
        long localFileHeaderOffset;
        void write(OutputStream out) throws IOException {
            var buffer = ByteBuffer.allocate(ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putShort(signature);
            buffer.putShort(size);
            buffer.putLong(originalSize);
            buffer.putLong(compressedSize);
            buffer.putLong(localFileHeaderOffset);

            out.write(buffer.array());
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
        }
    }

    private static class Zip64EndOfCDRecord {
        final int signature = 0x06064b50;
        final long recordSize = ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE - 12;
        final short versionMadeBy = ZIP_VERSION;
        final short versionToExtract = ZIP_VERSION;
        int diskNumber;
        int startDiskNumber;
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
    }
}