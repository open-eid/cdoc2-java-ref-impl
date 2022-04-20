package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.utils.InputStreamStatistics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;


/**
 * Utility class for dealing with tar gz stream/files. Only supports regular files (no directories/special files) inside
 * tar. Concatenated gzip streams are not supported.
 */
public final class Tar {

    private static final Logger log = LoggerFactory.getLogger(Tar.class);


    private static final int DEFAULT_BUFFER_SIZE  = 8192;
    private static final double MAX_COMPRESSION_RATIO = 10;

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

    public static void archiveFiles(OutputStream dest, Iterable<File> files)
            throws IOException {

        List<String> baseNameList = new LinkedList<>();
        files.forEach(f -> baseNameList.add(f.getName()));
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

        try (TarArchiveOutputStream tos = new TarArchiveOutputStream(new GzipCompressorOutputStream(
                new BufferedOutputStream(dest)))) {
            tos.setAddPaxHeadersForNonAsciiNames(true);
            for (File file : files) {
                addFileToTar(tos, file.toPath(), file.getName());
            }
        }
    }

    /**
     * Create an archive with single entry.
     * @param dest destination stream where created archive will be written
     * @param inputStream data added to archive
     * @param tarEntryName entry name (file name) for data
     * @throws IOException if an I/O error has occurred
     */
    public static void archiveData(OutputStream dest, InputStream inputStream, String tarEntryName) throws IOException {
        try (TarArchiveOutputStream tarOs = new TarArchiveOutputStream(new GzipCompressorOutputStream(
                new BufferedOutputStream(dest)))) {
            tarOs.setAddPaxHeadersForNonAsciiNames(true);
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
     * Extract single file into outputStream
     * @param tarGZipInputStream GZipped and tarred input stream that is scanned for tarEntryName
     * @param outputStream OutputStream to write tarEntry contents
     * @param tarEntryName file to extract
     * @return bytes written to outputStream or -1 if tarEntryName was not found from tarGZip
     * @throws IOException if an I/O error has occurred
     */
    public static long extractTarEntry(InputStream tarGZipInputStream, OutputStream outputStream, String tarEntryName)
            throws IOException {

        try (TarArchiveInputStream tarInputStream = new TarArchiveInputStream(new GzipCompressorInputStream(
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
     * @param filesToExtract if not null, extract specified files otherwise all files
     * @param extract if true, extract files to outputDir. Otherwise, list TarArchiveEntries
     * @return List<ArchiveEntry> list of TarArchiveEntry processed in tarGZipInputStream (ignored entries are not
     *      returned)
     * @throws IOException if an I/O error has occurred
     */
    static List<ArchiveEntry> processTarGz(InputStream tarGZipIs, Path outputDir,
                                           List<String> filesToExtract, boolean extract) throws IOException {

        if (extract && (!Files.isDirectory(outputDir) || !Files.isWritable(outputDir))) {
            throw new IOException("Not directory or not writeable " + outputDir);
        }

        if (extract) {
            log.info("Extracting to {}", outputDir.normalize());
        }

        List<ArchiveEntry> extractedArchiveEntries = new LinkedList<>();
        List<File> extractedFiles = new LinkedList<>();
        try (GzipCompressorInputStream gZipIs = new GzipCompressorInputStream(new BufferedInputStream(tarGZipIs));
             TarArchiveInputStream tarInputStream = new TarArchiveInputStream(gZipIs)) {


            int tarEntriesThreshold = getDefaultTarEntriesThresholdThreshold();
            TarArchiveEntry tarArchiveEntry;
            while ((tarArchiveEntry = tarInputStream.getNextTarEntry()) != null) {
                if (tarArchiveEntry.isFile()) {
                    log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                    if (extract) { //extract
                        File extractedFile = copyTarEntryToDirectory(outputDir, tarInputStream, tarArchiveEntry, gZipIs,
                                filesToExtract);
                        if (extractedFile != null) {

                            extractedArchiveEntries.add(tarArchiveEntry);
                            extractedFiles.add(extractedFile);

                            if (extractedArchiveEntries.size() > tarEntriesThreshold) {
                                log.error("Tar entries threshold ({}) exceeded.", tarEntriesThreshold);
                                throw new IllegalStateException("Tar entries threshold exceeded. Aborting.");
                            }

                        }
                    } else { //list
                        extractedArchiveEntries.add(tarArchiveEntry);
                    }
                } else {
                    log.info("Ignored non-regular file {}", tarArchiveEntry.getName());
                }
            }
        } catch (Throwable t) {
            log.info("Exception {}. Deleting already extracted files {}", t, extractedFiles);
            deleteFiles(extractedFiles);
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
     *
     * @param outputDir output directory where files are extracted
     * @param tarInputStream tar InputStream to process
     * @param tarArchiveEntry TarArchiveEntry read from TarArchiveInputStream and currently under processing
     * @param gZipStatistics InputStreamStatistics from GZip stream
     * @param filesToExtract if not null, extract specified files otherwise all files
     * @return File extracted from tarArchiveEntry or null if File was not created
     * @throws IOException if an I/O error has occurred
     */
    private static File copyTarEntryToDirectory(Path outputDir,
                                                   TarArchiveInputStream tarInputStream,
                                                   TarArchiveEntry tarArchiveEntry,
                                                   InputStreamStatistics gZipStatistics,
                                                   List<String> filesToExtract)
            throws IOException {

        if ((filesToExtract == null) || filesToExtract.contains(tarArchiveEntry.getName())) {
            return copyTarEntryToDirectory(outputDir, tarInputStream, tarArchiveEntry, gZipStatistics);
        }
        return null;
    }

    /**
     * Extract tar entry as File in outputDir
     * @param outputDir directory where file will be created
     * @param tarInputStream read file contents from tarInputStream
     * @param tarArchiveEntry tarArchiveEntry to extract
     * @param gZipStatistics wrapping compression statistics
     * @return File created from tar
     * @throws IOException if an I/O error has occurred
     */
    private static File copyTarEntryToDirectory(Path outputDir, TarArchiveInputStream tarInputStream,
                                                TarArchiveEntry tarArchiveEntry, InputStreamStatistics gZipStatistics)
            throws IOException {

        if (tarArchiveEntry.getName() == null) {
            throw new IOException("Invalid tarEntry without name");
        }

        Path tarPath = Path.of(tarArchiveEntry.getName());
        if (null != tarPath.getParent()) {
            log.debug("Entries with directories are not supported {}", tarArchiveEntry.getName());
            throw new IOException("Entries with directories are not supported ("
                    + tarArchiveEntry.getName() + ")");
        }

        Path newPath = Path.of(outputDir.toString()).resolve(tarPath.getFileName()).normalize();
        if (!newPath.startsWith(outputDir)) {
            throw new IOException(tarArchiveEntry.getName() + " creates file outside of " + outputDir);
        }

        if (!isOverWriteAllowed() && Files.exists(newPath)) {
            log.info("File {} already exists.", newPath.toAbsolutePath());
            throw new FileAlreadyExistsException(newPath.toAbsolutePath().toString());
        }

        double diskUsageThreshold = getDiskUsedPercentageThreshold();


        long written = 0;
        // truncate and overwrite an existing file, or create the file if
        // it doesn't initially exist
        try (OutputStream out = Files.newOutputStream(newPath)) {
            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = tarInputStream.read(buffer, 0, DEFAULT_BUFFER_SIZE)) >= 0) {

                double usedPercentage = (double)outputDir.toFile().getUsableSpace()
                        / (double)outputDir.toFile().getTotalSpace() * 100;

                if (usedPercentage >= diskUsageThreshold) {
                    String err = String.format("More than  %.2f%% disk space used. Aborting", diskUsageThreshold);
                    log.error(err);
                    throw new IllegalStateException(err);
                }

                out.write(buffer, 0, read);
                written += read;

                double compressionRatio = (double)gZipStatistics.getUncompressedCount()
                        / (double)gZipStatistics.getCompressedCount();
                if (compressionRatio > MAX_COMPRESSION_RATIO) {
                    log.debug("Compression ratio for {} is {}", tarArchiveEntry.getName(), compressionRatio);
                    // ratio between compressed and uncompressed data is highly suspicious, looks like a Zip Bomb Attack
                    throw new IllegalStateException("Gzip compression ratio " + compressionRatio + " is over "
                            + MAX_COMPRESSION_RATIO);
                }
            }
        }

        log.debug("Created {} {}B", newPath, written);
        return newPath.toFile();
    }

    private static double getDiskUsedPercentageThreshold() {
        double diskUsageThreshold = DEFAULT_DISK_USED_PERCENTAGE_THRESHOLD;
        if (System.getProperties().containsKey("ee.cyber.cdoc20.maxDiskUsagePercentage")) {
            String maxDiskUsagePercentageStr = System.getProperty("ee.cyber.cdoc20.maxDiskUsagePercentage");
            try {
                diskUsageThreshold = Double.parseDouble(maxDiskUsagePercentageStr);
            } catch (NumberFormatException nfe) {
                log.warn("Invalid value {} for ee.cyber.cdoc20.maxDiskUsagePercentage. Using default {}",
                        maxDiskUsagePercentageStr, DEFAULT_DISK_USED_PERCENTAGE_THRESHOLD);
            }
        }
        return diskUsageThreshold;
    }

    private static int getDefaultTarEntriesThresholdThreshold() {
        int tarEntriesThreshold = DEFAULT_TAR_ENTRIES_THRESHOLD;
        if (System.getProperties().containsKey("ee.cyber.cdoc20.tarEntriesThreshold")) {
            String tarEntriesThresholdStr = System.getProperty("ee.cyber.cdoc20.tarEntriesThreshold");
            try {
                tarEntriesThreshold = Integer.parseInt(tarEntriesThresholdStr);
            } catch (NumberFormatException nfe) {
                log.warn("Invalid value {} for ee.cyber.cdoc20.tarEntriesThreshold. Using default {}",
                        tarEntriesThresholdStr, DEFAULT_TAR_ENTRIES_THRESHOLD);
            }
        }
        return tarEntriesThreshold;
    }

    private static boolean isOverWriteAllowed() {
        boolean overwrite = DEFAULT_OVERWRITE;
        if (System.getProperties().containsKey("ee.cyber.cdoc20.overwrite")) {
            String overwriteStr = System.getProperty("ee.cyber.cdoc20.overwrite");

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
