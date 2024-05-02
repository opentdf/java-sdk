package io.opentdf.platform.sdk;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

public class ZipWriter {

    private enum WriteState {Initial, Appending, Finished}

    private static final int ZIP_VERSION = 20;
    private static final int ZIP_64_MAGIC_VAL = 0xFFFFFFFF;
    private static final int ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE = 24;
    private static final int ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE = 28;
    private static final int ZIP_32_DATA_DESCRIPTOR_SIZE = 16;
    private static final int HALF_SECOND = 2;
    private static final int BASE_YEAR = 1980;
    private static final int DEFAULT_SECOND_VALUE = 29;
    private static final int MONTH_SHIFT = 5;

    private OutputStream writer;
    private long currentOffset;
    private long lastOffsetCDFileHeader;
    private FileInfo fileInfo;
    private List<FileInfo> fileInfoEntries;
    private WriteState writeState;
    private boolean isZip64;
    private long totalBytes;

    public ZipWriter(OutputStream writer) {
        this.writer = writer;
        this.currentOffset = 0;
        this.lastOffsetCDFileHeader = 0;
        this.fileInfo = new FileInfo();
        this.fileInfoEntries = new ArrayList<>();
        this.writeState = WriteState.Initial;
        this.isZip64 = false;
        this.totalBytes = 0;
    }

    public void enableZip64() {
        this.isZip64 = true;
    }

    public void addHeader(String filename, long size) throws IOException {
        if (filename == null || filename.isEmpty()) {
            throw new IllegalArgumentException("Filename cannot be null or empty");
        }

        if (this.writeState != WriteState.Initial && this.writeState != WriteState.Finished) {
            throw new IOException("Cannot add a new file until the current file write is completed: " + this.fileInfo.filename);
        }

        this.fileInfo = new FileInfo();
        this.fileInfo.filename = filename;

        if (!this.isZip64) {
            this.isZip64 = size > 4L * 1024 * 1024 * 1024; // if file size is greater than 4GB
        }

        this.writeState = WriteState.Initial;
        this.fileInfo.size = size;
        this.fileInfo.filename = filename;
    }

    public void addData(byte[] data) throws IOException {
        long fileTime, fileDate;
        fileTime = fileDate = getTimeDateUnMSDosFormat();

        if (this.writeState == WriteState.Initial) {
            LocalFileHeader localFileHeader = new LocalFileHeader();
            localFileHeader.signature = 0x04034b50;
            localFileHeader.version = ZIP_VERSION;
            localFileHeader.generalPurposeBitFlag = 0x08;
            localFileHeader.compressionMethod = 0;
            localFileHeader.lastModifiedTime = (int) fileTime;
            localFileHeader.lastModifiedDate = (int) fileDate;
            localFileHeader.crc32 = 0;
            localFileHeader.compressedSize = 0;
            localFileHeader.uncompressedSize = 0;
            localFileHeader.extraFieldLength = 0;

            if (this.isZip64) {
                localFileHeader.compressedSize = ZIP_64_MAGIC_VAL;
                localFileHeader.uncompressedSize = ZIP_64_MAGIC_VAL;
                localFileHeader.extraFieldLength = ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE;
            }

            localFileHeader.filenameLength = (short) this.fileInfo.filename.length();

            // Write local file header
            ByteBuffer buffer = ByteBuffer.allocate(30 + this.fileInfo.filename.length());
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(localFileHeader.signature);
            buffer.putShort((short) localFileHeader.version);
            buffer.putShort((short) localFileHeader.generalPurposeBitFlag);
            buffer.putShort((short) localFileHeader.compressionMethod);
            buffer.putShort((short) localFileHeader.lastModifiedTime);
            buffer.putShort((short) localFileHeader.lastModifiedDate);
            buffer.putInt(localFileHeader.crc32);
            buffer.putInt(localFileHeader.compressedSize);
            buffer.putInt(localFileHeader.uncompressedSize);
            buffer.putShort(localFileHeader.filenameLength);
            buffer.putShort(localFileHeader.extraFieldLength);
            buffer.put(this.fileInfo.filename.getBytes(StandardCharsets.UTF_8));

            this.writer.write(buffer.array());

            if (this.isZip64) {
                Zip64ExtendedLocalInfoExtraField zip64ExtendedLocalInfoExtraField = new Zip64ExtendedLocalInfoExtraField();
                zip64ExtendedLocalInfoExtraField.signature = 0x0001;
                zip64ExtendedLocalInfoExtraField.size = ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE - 4;
                zip64ExtendedLocalInfoExtraField.originalSize = this.fileInfo.size;
                zip64ExtendedLocalInfoExtraField.compressedSize = this.fileInfo.size;

                buffer = ByteBuffer.allocate(ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putShort((short) zip64ExtendedLocalInfoExtraField.signature);
                buffer.putShort((short) zip64ExtendedLocalInfoExtraField.size);
                buffer.putLong(zip64ExtendedLocalInfoExtraField.originalSize);
                buffer.putLong(zip64ExtendedLocalInfoExtraField.compressedSize);

                this.writer.write(buffer.array());
            }

            this.writeState = WriteState.Appending;
            this.fileInfo.crc = new CRC32().getValue();
            this.fileInfo.fileTime = (short) fileTime;
            this.fileInfo.fileDate = (short) fileDate;
        }

        // Write the data contents
        this.writer.write(data);

        // Update CRC32
        CRC32 crc32 = new CRC32();
        crc32.update(data);
        this.fileInfo.crc = crc32.getValue();

        // Update file size
        this.fileInfo.offset += data.length;

        // Check if we reached the end
        if (this.fileInfo.offset >= this.fileInfo.size) {
            this.writeState = WriteState.Finished;
            this.fileInfo.offset = this.currentOffset;
            this.fileInfo.flag = 0x08;
            this.fileInfoEntries.add(this.fileInfo);
        }

        if (this.writeState == WriteState.Finished) {
            if (this.isZip64) {
                // Write Zip64 data descriptor
                Zip64DataDescriptor zip64DataDescriptor = new Zip64DataDescriptor();
                zip64DataDescriptor.signature = 0x08074b50;
                zip64DataDescriptor.crc32 = this.fileInfo.crc;
                zip64DataDescriptor.compressedSize = this.fileInfo.size;
                zip64DataDescriptor.uncompressedSize = this.fileInfo.size;

                ByteBuffer buffer = ByteBuffer.allocate(ZIP_32_DATA_DESCRIPTOR_SIZE);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(zip64DataDescriptor.signature);
                buffer.putInt((int) zip64DataDescriptor.crc32);
                buffer.putInt((int) zip64DataDescriptor.compressedSize);
                buffer.putInt((int) zip64DataDescriptor.uncompressedSize);

                this.writer.write(buffer.array());

                this.currentOffset += 30 + this.fileInfo.filename.length() + this.fileInfo.size + ZIP_64_EXTENDED_LOCAL_INFO_EXTRA_FIELD_SIZE + ZIP_32_DATA_DESCRIPTOR_SIZE;
            } else {
                // Write Zip32 data descriptor
                Zip32DataDescriptor zip32DataDescriptor = new Zip32DataDescriptor();
                zip32DataDescriptor.signature = 0x08074b50;
                zip32DataDescriptor.crc32 = this.fileInfo.crc;
                zip32DataDescriptor.compressedSize = (int) this.fileInfo.size;
                zip32DataDescriptor.uncompressedSize = (int) this.fileInfo.size;

                ByteBuffer buffer = ByteBuffer.allocate(ZIP_32_DATA_DESCRIPTOR_SIZE);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(zip32DataDescriptor.signature);
                buffer.putInt((int) zip32DataDescriptor.crc32);
                buffer.putInt(zip32DataDescriptor.compressedSize);
                buffer.putInt(zip32DataDescriptor.uncompressedSize);

                this.writer.write(buffer.array());

                this.currentOffset += 30 + this.fileInfo.filename.length() + this.fileInfo.size + ZIP_32_DATA_DESCRIPTOR_SIZE;
            }

            this.fileInfo = new FileInfo();
        }
    }

    public void finish() throws IOException {
        writeCentralDirectory();
        writeEndOfCentralDirectory();
    }

    private void writeCentralDirectory() throws IOException {
        this.lastOffsetCDFileHeader = this.currentOffset;

        for (FileInfo fileInfo : this.fileInfoEntries) {
            CDFileHeader cdFileHeader = new CDFileHeader();
            cdFileHeader.signature = 0x02014b50;
            cdFileHeader.versionCreated = ZIP_VERSION;
            cdFileHeader.versionNeeded = ZIP_VERSION;
            cdFileHeader.generalPurposeBitFlag = fileInfo.flag;
            cdFileHeader.compressionMethod = 0;
            cdFileHeader.lastModifiedTime = fileInfo.fileTime;
            cdFileHeader.lastModifiedDate = fileInfo.fileDate;
            cdFileHeader.crc32 = (int) fileInfo.crc;
            cdFileHeader.filenameLength = (short) fileInfo.filename.length();
            cdFileHeader.fileCommentLength = 0;
            cdFileHeader.diskNumberStart = 0;
            cdFileHeader.internalFileAttributes = 0;
            cdFileHeader.externalFileAttributes = 0;
            cdFileHeader.compressedSize = (int) fileInfo.size;
            cdFileHeader.uncompressedSize = (int) fileInfo.size;
            cdFileHeader.localHeaderOffset = (int) fileInfo.offset;
            cdFileHeader.extraFieldLength = 0;

            if (this.isZip64) {
                cdFileHeader.compressedSize = ZIP_64_MAGIC_VAL;
                cdFileHeader.uncompressedSize = ZIP_64_MAGIC_VAL;
                cdFileHeader.localHeaderOffset = ZIP_64_MAGIC_VAL;
                cdFileHeader.extraFieldLength = ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE;
            }

            ByteBuffer buffer = ByteBuffer.allocate(46 + fileInfo.filename.length());
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(cdFileHeader.signature);
            buffer.putShort((short) cdFileHeader.versionCreated);
            buffer.putShort((short) cdFileHeader.versionNeeded);
            buffer.putShort((short) cdFileHeader.generalPurposeBitFlag);
            buffer.putShort((short) cdFileHeader.compressionMethod);
            buffer.putShort((short) cdFileHeader.lastModifiedTime);
            buffer.putShort((short) cdFileHeader.lastModifiedDate);
            buffer.putInt((int) cdFileHeader.crc32);
            buffer.putInt(cdFileHeader.compressedSize);
            buffer.putInt(cdFileHeader.uncompressedSize);
            buffer.putShort(cdFileHeader.filenameLength);
            buffer.putShort(cdFileHeader.fileCommentLength);
            buffer.putShort(cdFileHeader.diskNumberStart);
            buffer.putShort(cdFileHeader.internalFileAttributes);
            buffer.putInt(cdFileHeader.externalFileAttributes);
            buffer.putInt(cdFileHeader.localHeaderOffset);
            buffer.putShort(cdFileHeader.extraFieldLength);
            buffer.put(fileInfo.filename.getBytes(StandardCharsets.UTF_8));

            this.writer.write(buffer.array());

            if (this.isZip64) {
                Zip64ExtendedInfoExtraField zip64ExtendedInfoExtraField = new Zip64ExtendedInfoExtraField();
                zip64ExtendedInfoExtraField.signature = 0x0001;
                zip64ExtendedInfoExtraField.size = ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE - 4;
                zip64ExtendedInfoExtraField.originalSize = fileInfo.size;
                zip64ExtendedInfoExtraField.compressedSize = fileInfo.size;
                zip64ExtendedInfoExtraField.localFileHeaderOffset = fileInfo.offset;

                buffer = ByteBuffer.allocate(ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putShort((short) zip64ExtendedInfoExtraField.signature);
                buffer.putShort((short) zip64ExtendedInfoExtraField.size);
                buffer.putLong(zip64ExtendedInfoExtraField.originalSize);
                buffer.putLong(zip64ExtendedInfoExtraField.compressedSize);
                buffer.putLong(zip64ExtendedInfoExtraField.localFileHeaderOffset);

                this.writer.write(buffer.array());
            }

            this.lastOffsetCDFileHeader += 46 + fileInfo.filename.length();

            if (this.isZip64) {
                this.lastOffsetCDFileHeader += ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE;
            }
        }
    }

    private void writeEndOfCentralDirectory() throws IOException {
        if (this.isZip64) {
            writeZip64EndOfCentralDirectory();
            writeZip64EndOfCentralDirectoryLocator();
        }

        EndOfCDRecord endOfCDRecord = new EndOfCDRecord();
        endOfCDRecord.signature = 0x06054b50;
        endOfCDRecord.diskNumber = 0;
        endOfCDRecord.startDiskNumber = 0;
        endOfCDRecord.numberOfCDRecordEntries = (short) this.fileInfoEntries.size();
        endOfCDRecord.totalCDRecordEntries = (short) this.fileInfoEntries.size();
        endOfCDRecord.centralDirectoryOffset = (int) this.currentOffset;
        endOfCDRecord.sizeOfCentralDirectory = (int) (this.lastOffsetCDFileHeader - this.currentOffset);
        endOfCDRecord.commentLength = 0;

        ByteBuffer buffer = ByteBuffer.allocate(22);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(endOfCDRecord.signature);
        buffer.putShort(endOfCDRecord.diskNumber);
        buffer.putShort(endOfCDRecord.startDiskNumber);
        buffer.putShort(endOfCDRecord.numberOfCDRecordEntries);
        buffer.putShort(endOfCDRecord.totalCDRecordEntries);
        buffer.putInt(endOfCDRecord.sizeOfCentralDirectory);
        buffer.putInt(endOfCDRecord.centralDirectoryOffset);
        buffer.putShort(endOfCDRecord.commentLength);

        this.writer.write(buffer.array());
    }

    private void writeZip64EndOfCentralDirectory() throws IOException {
        Zip64EndOfCDRecord zip64EndOfCDRecord = new Zip64EndOfCDRecord();
        zip64EndOfCDRecord.signature = 0x06064b50;
        zip64EndOfCDRecord.recordSize = ZIP_64_EXTENDED_INFO_EXTRA_FIELD_SIZE - 12;
        zip64EndOfCDRecord.versionMadeBy = ZIP_VERSION;
        zip64EndOfCDRecord.versionToExtract = ZIP_VERSION;
        zip64EndOfCDRecord.diskNumber = 0;
        zip64EndOfCDRecord.startDiskNumber = 0;
        zip64EndOfCDRecord.numberOfCDRecordEntries = this.fileInfoEntries.size();
        zip64EndOfCDRecord.totalCDRecordEntries = this.fileInfoEntries.size();
        zip64EndOfCDRecord.centralDirectorySize = this.lastOffsetCDFileHeader - this.currentOffset;
        zip64EndOfCDRecord.startingDiskCentralDirectoryOffset = this.currentOffset;

        ByteBuffer buffer = ByteBuffer.allocate(56);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(zip64EndOfCDRecord.signature);
        buffer.putLong(zip64EndOfCDRecord.recordSize);
        buffer.putShort(zip64EndOfCDRecord.versionMadeBy);
        buffer.putShort(zip64EndOfCDRecord.versionToExtract);
        buffer.putInt(zip64EndOfCDRecord.diskNumber);
        buffer.putInt(zip64EndOfCDRecord.startDiskNumber);
        buffer.putLong(zip64EndOfCDRecord.numberOfCDRecordEntries);
        buffer.putLong(zip64EndOfCDRecord.totalCDRecordEntries);
        buffer.putLong(zip64EndOfCDRecord.centralDirectorySize);
        buffer.putLong(zip64EndOfCDRecord.startingDiskCentralDirectoryOffset);

        this.writer.write(buffer.array());
    }

    private void writeZip64EndOfCentralDirectoryLocator() throws IOException {
        Zip64EndOfCDRecordLocator zip64EndOfCDRecordLocator = new Zip64EndOfCDRecordLocator();
        zip64EndOfCDRecordLocator.signature = 0x07064b50;
        zip64EndOfCDRecordLocator.CDStartDiskNumber = 0;
        zip64EndOfCDRecordLocator.CDOffset = this.lastOffsetCDFileHeader;
        zip64EndOfCDRecordLocator.numberOfDisks = 1;

        ByteBuffer buffer = ByteBuffer.allocate(20);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(zip64EndOfCDRecordLocator.signature);
        buffer.putInt(zip64EndOfCDRecordLocator.CDStartDiskNumber);
        buffer.putLong(zip64EndOfCDRecordLocator.CDOffset);
        buffer.putInt(zip64EndOfCDRecordLocator.numberOfDisks);

        this.writer.write(buffer.array());
    }

    private long getTimeDateUnMSDosFormat() {
        LocalDateTime now = LocalDateTime.now();
        int timeInDos = now.getHour() << 11 | now.getMinute() << 5 | Math.max(now.getSecond() / HALF_SECOND, DEFAULT_SECOND_VALUE);
        int dateInDos = (now.getYear() - BASE_YEAR) << 9 | ((now.getMonthValue() + 1) << MONTH_SHIFT) | now.getDayOfMonth();
        return ((long) timeInDos << 16) | dateInDos;
    }

    private static class LocalFileHeader {
        int signature;
        int version;
        int generalPurposeBitFlag;
        int compressionMethod;
        int lastModifiedTime;
        int lastModifiedDate;
        int crc32;
        int compressedSize;
        int uncompressedSize;
        short filenameLength;
        short extraFieldLength;
    }

    private static class Zip64ExtendedLocalInfoExtraField {
        short signature;
        short size;
        long originalSize;
        long compressedSize;
    }

    private static class Zip64DataDescriptor {
        int signature;
        long crc32;
        long compressedSize;
        long uncompressedSize;
    }

    private static class Zip32DataDescriptor {
        int signature;
        long crc32;
        int compressedSize;
        int uncompressedSize;
    }

    private static class CDFileHeader {
        int signature;
        int versionCreated;
        int versionNeeded;
        int generalPurposeBitFlag;
        int compressionMethod;
        int lastModifiedTime;
        int lastModifiedDate;
        int crc32;
        int compressedSize;
        int uncompressedSize;
        short filenameLength;
        short fileCommentLength;
        short diskNumberStart;
        short internalFileAttributes;
        int externalFileAttributes;
        int localHeaderOffset;
        short extraFieldLength;
    }

    private static class Zip64ExtendedInfoExtraField {
        short signature;
        short size;
        long originalSize;
        long compressedSize;
        long localFileHeaderOffset;
    }

    private static class EndOfCDRecord {
        int signature;
        short diskNumber;
        short startDiskNumber;
        short numberOfCDRecordEntries;
        short totalCDRecordEntries;
        int sizeOfCentralDirectory;
        int centralDirectoryOffset;
        short commentLength;
    }

    private static class Zip64EndOfCDRecord {
        int signature;
        long recordSize;
        short versionMadeBy;
        short versionToExtract;
        int diskNumber;
        int startDiskNumber;
        long numberOfCDRecordEntries;
        long totalCDRecordEntries;
        long centralDirectorySize;
        long startingDiskCentralDirectoryOffset;
    }

    private static class Zip64EndOfCDRecordLocator {
        int signature;
        int CDStartDiskNumber;
        long CDOffset;
        int numberOfDisks;
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