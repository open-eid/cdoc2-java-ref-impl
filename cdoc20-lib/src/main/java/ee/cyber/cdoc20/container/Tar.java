package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream; //zlib
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;

import static ee.cyber.cdoc20.CDocConfiguration.DISK_USAGE_THRESHOLD_PROPERTY;
import static ee.cyber.cdoc20.CDocConfiguration.GZIP_COMPRESSION_THRESHOLD_PROPERTY;
import static ee.cyber.cdoc20.CDocConfiguration.TAR_ENTRIES_THRESHOLD_PROPERTY;

/**
 * Utility class for dealing with tar zlib (deflate) stream/files. Only supports regular files
 * (no directories/special files) inside the tar.
 */
public final class Tar {

    private static final Logger log = LoggerFactory.getLogger(Tar.class);

    public static final int DEFAULT_BUFFER_SIZE  = 8192;

    // gzip compression ratio threshold, normally less than 3, consider over 10 as zip bomb
    public static final double DEFAULT_COMPRESSION_RATIO_THRESHOLD = 10;

    // disk space available percentage allowed
    public static final double DEFAULT_DISK_USED_PERCENTAGE_THRESHOLD = 98;

    public static final int DEFAULT_TAR_ENTRIES_THRESHOLD = 1000;

    private Tar() {
    }



    static void addFileToTar(TarArchiveOutputStream outputStream, Path file, String entryName) throws IOException {

        log.debug("Adding file {} as {}", file.toAbsolutePath(), entryName);
        if (Files.isRegularFile(file)) {
            TarArchiveEntry tarArchiveEntry = (TarArchiveEntry) outputStream.createArchiveEntry(file.toFile(),
                    entryName);

            outputStream.putArchiveEntry(tarArchiveEntry);
            try (InputStream input = new BufferedInputStream(Files.newInputStream(file))) {
                long written = input.transferTo(outputStream);
                log.debug("Added {}B", written);
            }
        } else {
            throw new IOException("Not a file: " + file);
        }
        outputStream.closeArchiveEntry();
    }

    /**
     * Create tar archive of files and compress that with zlib.
     * @param dest Compressed tar is written to dest
     * @param files to archive
     * @throws IOException
     */
    public static void archiveFiles(OutputStream dest, Iterable<File> files) throws IOException {

        List<String> baseNameList = new LinkedList<>();
        files.forEach(f -> baseNameList.add(FileNameValidator.validate(f.getName())));
        List<String> distinctList = baseNameList.stream().distinct().toList();
        if (baseNameList.size() != distinctList.size()) {
            List<String> duplicates = baseNameList.stream()
                .filter(str -> Collections.frequency(baseNameList, str) > 1)
                .toList();

            List<File> duplicateFiles = new LinkedList<>();
            files.forEach(f -> {
                if (duplicates.contains(f.getName())) {
                    duplicateFiles.add(f);
                }
            });

            throw new IllegalArgumentException("Files with same basename not supported: " + duplicateFiles);
        }

        try (TarArchiveOutputStream tos = createPosixTarZArchiveOutputStream(dest)) {
            for (File file : files) {
                addFileToTar(tos, file.toPath(), file.getName());
            }
        }
    }

    /**
     * Create a compressed (zlib) archive with single entry.
     * @param dest destination stream where created archive will be written
     * @param inputStream data added to archive
     * @param tarEntryName entry name (file name) for data
     * @throws IOException if an I/O error has occurred
     */
    public static void archiveData(OutputStream dest, InputStream inputStream, String tarEntryName) throws IOException {
        try (TarArchiveOutputStream tarOs = createPosixTarZArchiveOutputStream(dest)) {

            TarArchiveEntry tarEntry = new TarArchiveEntry(tarEntryName);
            //log.debug("adding {}B", inputStream.available());
            tarEntry.setSize(inputStream.available());
            tarOs.putArchiveEntry(tarEntry);

            long written = inputStream.transferTo(tarOs);
            //log.debug("Wrote {}B", written);
            tarOs.closeArchiveEntry();
        }
    }

    /**
     * Create zlib/deflate compressed POSIX compliant TarArchiveOutputStream with UTF-8 filenames and POSIX long
     * filename and POSIX big file sizes (over 8GB) extensions enabled.
     */
    static TarArchiveOutputStream createPosixTarZArchiveOutputStream(OutputStream dest) throws IOException {
        TarArchiveOutputStream tarZOs = new TarArchiveOutputStream(new DeflateCompressorOutputStream(
                new BufferedOutputStream(dest)), StandardCharsets.UTF_8.name());
        tarZOs.setAddPaxHeadersForNonAsciiNames(true);
        tarZOs.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
        tarZOs.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
        return tarZOs;
    }

    /**
     * Extract single file into outputStream
     * @param tarGZipInputStream GZipped and tarred input stream that is scanned for tarEntryName
     * @param outputStream OutputStream to write tarEntry contents
     * @param tarEntryName file to extract
     * @return bytes written to outputStream or -1 if tarEntryName was not found from tarGZip
     * @throws IOException if an I/O error has occurred
     */
    public static long extractTarEntry(InputStream tarGZipInputStream, OutputStream outputStream, String tarEntryName)
            throws IOException {

        try (TarArchiveInputStream tarInputStream = new TarArchiveInputStream(new DeflateCompressorInputStream(
                new BufferedInputStream(tarGZipInputStream)))) {
            TarArchiveEntry tarArchiveEntry;
            while ((tarArchiveEntry = tarInputStream.getNextTarEntry()) != null) {
                if (tarArchiveEntry.isFile() && tarEntryName.equals(tarArchiveEntry.getName())) {
                    log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                    long written = tarInputStream.transferTo(outputStream);
                    log.debug("Copied {}B", written);
                    return written;
                }
            }
        }

        log.info("not found {}", tarEntryName);
        return -1L;
    }

    public static double getDiskUsedPercentageThreshold() {
        return getNumberPropertyValue(DISK_USAGE_THRESHOLD_PROPERTY, DEFAULT_DISK_USED_PERCENTAGE_THRESHOLD,
                Double::valueOf);
    }

    public static int getTarEntriesThresholdThreshold() {
        return getNumberPropertyValue(TAR_ENTRIES_THRESHOLD_PROPERTY, DEFAULT_TAR_ENTRIES_THRESHOLD, Integer::valueOf);
    }

    public static double getCompressionRatioThreshold() {
        return getNumberPropertyValue(GZIP_COMPRESSION_THRESHOLD_PROPERTY,
                DEFAULT_COMPRESSION_RATIO_THRESHOLD, Double::valueOf);
    }

    private static <N extends Number> N getNumberPropertyValue(String propertyName, N defaultValue,
                                                               Function<String, N> strToNumFunc) {
        N value = defaultValue;
        if (System.getProperties().containsKey(propertyName)) {
            String propertyValueStr = System.getProperty(propertyName);
            try {
                value = strToNumFunc.apply(propertyValueStr);
            } catch (NumberFormatException nfe) {
                log.warn("Invalid value {} for {}. Using default {}",
                        propertyValueStr, propertyName, defaultValue);
            }
        }
        return value;
    }

}
