package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.CDocConfiguration;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream; //zlib
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.utils.InputStreamStatistics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
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
 * Utility class for dealing with tar zlib stream/files. Only supports regular files (no directories/special files)
 * inside the tar. Concatenated gzip streams are not supported.
 */
public final class Tar {

    private static final Logger log = LoggerFactory.getLogger(Tar.class);


    private static final int DEFAULT_BUFFER_SIZE  = 8192;

    // gzip compression ratio threshold, normally less than 3, consider over 10 as zip bomb
    private static final double DEFAULT_COMPRESSION_RATIO_THRESHOLD = 10;

    // disk space available percentage allowed
    private static final double DEFAULT_DISK_USED_PERCENTAGE_THRESHOLD = 98;

    private static final int DEFAULT_TAR_ENTRIES_THRESHOLD = 1000;

    // whether overwrite of extracted files is allowed
    private static final boolean DEFAULT_OVERWRITE = true;

    private Tar() {
    }

    static void addFileToTar(TarArchiveOutputStream tarArchiveOutputStream, Path file, String entryName)
            throws IOException {

        log.debug("Adding file {} as {}", file.toAbsolutePath(), entryName);
        if (Files.isRegularFile(file)) {
            TarArchiveEntry tarArchiveEntry = (TarArchiveEntry) tarArchiveOutputStream.createArchiveEntry(file.toFile(),
                    entryName);

            tarArchiveOutputStream.putArchiveEntry(tarArchiveEntry);
            try (InputStream input = new BufferedInputStream(Files.newInputStream(file))) {
                long written = input.transferTo(tarArchiveOutputStream);
                log.debug("Added {}B", written);
            }
        } else {
            throw new IOException("Not a file: " + file);
        }
        tarArchiveOutputStream.closeArchiveEntry();
    }

    /**
     * Create tar archive of files and compress that with zlib.
     * @param dest Compressed tar is written to dest
     * @param files to archive
     * @throws IOException
     */
    public static void archiveFiles(OutputStream dest, Iterable<File> files)
            throws IOException {

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
     * Create zlib compressed POSIX compliant TarArchiveOutputStream with UTF-8 filenames and POSIX long filename and
     * POSIX big file sizes (over 8GB) extensions enabled.
     */
    private static TarArchiveOutputStream createPosixTarZArchiveOutputStream(OutputStream dest) throws IOException {
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
        return -1;
    }

    /**
     * Process tar gzip input stream and find entries in it. If extract is true, then files found from inputStream are
     * copied to outputDir.
     * @param tarGZipIs tar gzip InputStream to process
     * @param outputDir output directory where files are extracted when extract=true
     * @param filesToExtract if not null, extract specified files otherwise all files.
     *                      No effect for list (extract=false)
     * @param extract if true, extract files to outputDir. Otherwise, list TarArchiveEntries
     * @return List<ArchiveEntry> list of TarArchiveEntry processed in tarGZipInputStream (ignored entries are not
     *      returned)
     * @throws IOException if an I/O error has occurred
     */
    static List<ArchiveEntry> processTarGz(InputStream tarGZipIs, @Nullable Path outputDir,
                                           @Nullable List<String> filesToExtract, boolean extract) throws IOException {

        if (extract && (!Files.isDirectory(outputDir) || !Files.isWritable(outputDir))) {
            throw new IOException("Not directory or not writeable " + outputDir);
        }

        if (extract) {
            log.info("Extracting to {}", outputDir.normalize());
        }

        List<ArchiveEntry> extractedArchiveEntries = new LinkedList<>();
        List<File> createdFiles = new LinkedList<>();
        try (DeflateCompressorInputStream zLibIs = new DeflateCompressorInputStream(new BufferedInputStream(tarGZipIs));
             TarArchiveInputStream tarInputStream = new TarArchiveInputStream(zLibIs)) {

            int tarEntriesThreshold = getTarEntriesThresholdThreshold();
            TarArchiveEntry tarArchiveEntry;
            while ((tarArchiveEntry = tarInputStream.getNextTarEntry()) != null) {
                if (tarArchiveEntry.isFile()) {
                    log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                    //extract
                    if (extract &&  ((filesToExtract == null) || filesToExtract.contains(tarArchiveEntry.getName()))) {

                        Path destPath = pathFromTarEntry(outputDir, tarArchiveEntry, true);
                        createdFiles.add(destPath.toFile());
                        copyTarEntryToFile(destPath, tarInputStream, tarArchiveEntry, zLibIs);

                        extractedArchiveEntries.add(tarArchiveEntry);
                        if (extractedArchiveEntries.size() > tarEntriesThreshold) {
                            log.error("Tar entries threshold ({}) exceeded.", tarEntriesThreshold);
                            throw new IllegalStateException("Tar entries threshold exceeded. Aborting.");
                        }
                    } else { //list
                        extractedArchiveEntries.add(tarArchiveEntry);
                    }
                } else {
                    log.info("Ignored non-regular file {}", tarArchiveEntry.getName());
                }
            }
        } catch (Throwable t) {
            log.info("Exception {}. Deleting already extracted files {}", t, createdFiles);
            deleteFiles(createdFiles);
            throw t;
        }

        return extractedArchiveEntries;
    }

    private static void deleteFiles(List<File> filesToDelete) {
        for (File f: filesToDelete) {
            try {
                Files.deleteIfExists(f.toPath());
            } catch (IOException e) {
                log.error("Error deleting file {}", f.getAbsolutePath());
            }
        }
    }

    /**
     * Return Path from tarArchiveEntry under outputDir. Checks for different zip/tar file attacks.
     * @param outputDir output directory where files are extracted
     * @param tarArchiveEntry TarArchiveEntry read from TarArchiveInputStream and currently under processing
     * @param createFile whether to create path returned
     * @return Path, if outputDir and tarArchiveEntry are valid
     * @throws IOException if path cannot be created from tarArchiveEntry under outputDir
     */
    private static Path pathFromTarEntry(Path outputDir, TarArchiveEntry tarArchiveEntry, boolean createFile)
            throws IOException {

        if (tarArchiveEntry.getName() == null) {
            throw new IOException("Invalid tarEntry without name");
        }

        Path tarPath = Path.of(FileNameValidator.validate(tarArchiveEntry.getName()));
        if (null != tarPath.getParent()) {
            log.debug("Entries with directories are not supported {}", tarArchiveEntry.getName());
            throw new IOException("Entries with directories are not supported ("
                    + tarArchiveEntry.getName() + ")");
        }

        Path absOutDir = outputDir.normalize().toAbsolutePath();

        Path newPath = Path.of(absOutDir.toString()).resolve(tarPath.getFileName()).normalize();
        if (!newPath.startsWith(absOutDir)) {
            throw new IOException(tarArchiveEntry.getName() + " creates file outside of " + absOutDir);
        }

        if (!isOverWriteAllowed() && Files.exists(newPath)) {
            log.info("File {} already exists.", newPath.toAbsolutePath());
            throw new FileAlreadyExistsException(newPath.toAbsolutePath().toString());
        }

        if (createFile && !Files.exists(newPath)) {
            boolean created = newPath.toFile().createNewFile();
            if (!created) {
                log.warn("Failed to create {}", newPath);
            }
        }

        return newPath;
    }

    /**
     * Copy contents of tar entry to file
     * @param destPath Path where tar entry contents are saved
     * @param tarInputStream tar InputStream to process
     * @param tarArchiveEntry TarArchiveEntry read from TarArchiveInputStream and currently under processing
     * @param gZipStatistics InputStreamStatistics from GZip stream
     * @return File size created
     * @throws IOException if an I/O error has occurred
     */
    private static long copyTarEntryToFile(Path destPath, TarArchiveInputStream tarInputStream,
                                                TarArchiveEntry tarArchiveEntry, InputStreamStatistics gZipStatistics)
        throws IOException {

        double diskUsageThreshold = getDiskUsedPercentageThreshold();
        long written = 0;
        // truncate and overwrite an existing file, or create the file if
        // it doesn't initially exist
        try (OutputStream out = Files.newOutputStream(destPath)) {
            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = tarInputStream.read(buffer, 0, DEFAULT_BUFFER_SIZE)) >= 0) {

                double usedPercentage = (double)destPath.toFile().getUsableSpace()
                        / (double)destPath.toFile().getTotalSpace() * 100;

                if (usedPercentage >= diskUsageThreshold) {
                    String err = String.format("More than  %.2f%% disk space used. Aborting", diskUsageThreshold);
                    log.error(err);
                    throw new IllegalStateException(err);
                }

                out.write(buffer, 0, read);
                written += read;

                double compressionRatioThreshold = getCompressionRatioThreshold();
                double compressionRatio = (double)gZipStatistics.getUncompressedCount()
                        / (double)gZipStatistics.getCompressedCount();
                if (compressionRatio > compressionRatioThreshold) {
                    log.debug("Compression ratio for {} is {}", tarArchiveEntry.getName(), compressionRatio);
                    // ratio between compressed and uncompressed data is highly suspicious, looks like a Zip Bomb Attack
                    throw new IllegalStateException("Gzip compression ratio " + compressionRatio + " is over "
                            + compressionRatioThreshold);
                }
            }
        }

        log.debug("Created {} {}B", destPath, written);
        return written;
    }

    private static double getDiskUsedPercentageThreshold() {
        return getNumberPropertyValue(DISK_USAGE_THRESHOLD_PROPERTY, DEFAULT_DISK_USED_PERCENTAGE_THRESHOLD,
                Double::valueOf);
    }

    private static int getTarEntriesThresholdThreshold() {
        return getNumberPropertyValue(TAR_ENTRIES_THRESHOLD_PROPERTY, DEFAULT_TAR_ENTRIES_THRESHOLD, Integer::valueOf);
    }

    private static double getCompressionRatioThreshold() {
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

    private static boolean isOverWriteAllowed() {
        boolean overwrite = DEFAULT_OVERWRITE;
        if (System.getProperties().containsKey(CDocConfiguration.OVERWRITE_PROPERTY)) {
            String overwriteStr = System.getProperty(CDocConfiguration.OVERWRITE_PROPERTY);

            if (overwriteStr != null) {
                //only "true" is considered as true
                overwrite = Boolean.parseBoolean(overwriteStr);
            }
        }
        return overwrite;

    }


    public static List<ArchiveEntry> extractToDir(InputStream tarGZipInputStream, Path outputDir) throws IOException {
        return processTarGz(tarGZipInputStream, outputDir, null, true);
    }

    public static List<ArchiveEntry> listEntries(InputStream tarGZipInputStream) throws IOException {
        return processTarGz(tarGZipInputStream, null, null, false);
    }

    public static List<String> listFiles(InputStream tarGZipInputStream) throws IOException {
        return processTarGz(tarGZipInputStream, null, null, false).stream()
                .map(ArchiveEntry::getName)
                .toList();
    }
}
