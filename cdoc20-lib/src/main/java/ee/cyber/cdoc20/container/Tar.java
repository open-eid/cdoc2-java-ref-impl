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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;
//import java.util.zip.GZIPInputStream;
//import java.util.zip.GZIPOutputStream;

/**
 * Utility class for dealing with tar gz stream/files. Only supports regular files (no directories/special files) inside
 * tar. Concatenated gzip streams are not supported.
 */
public final class Tar {

    private static final Logger log = LoggerFactory.getLogger(Tar.class);


    private static final int DEFAULT_BUFFER_SIZE  = 8192;
    private static final double MAX_COMPRESSION_RATIO = 10;

    // disk space available percentage allowed
    private static final double DEFAULT_MAX_USED_PERCENTAGE = 98;

//    static {
//        MAX_USED_PERCENTAGE = Double.parseDouble(System.getProperty("ee.cyber.cdoc20.maxDiskUsagePercentage"));
//    }


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

        try (TarArchiveOutputStream tos = new TarArchiveOutputStream(new GzipCompressorOutputStream(
                new BufferedOutputStream(dest)))) {
            tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
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
     * @throws IOException
     */
    public static void archiveData(OutputStream dest, InputStream inputStream, String tarEntryName) throws IOException {
        try (TarArchiveOutputStream tarOs = new TarArchiveOutputStream(new GzipCompressorOutputStream(
                new BufferedOutputStream(dest)))) {
            tarOs.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
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
                    //TODO: check compression ratio
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

        LinkedList<ArchiveEntry> result = new LinkedList<>();
        try (GzipCompressorInputStream gZipIs = new GzipCompressorInputStream(new BufferedInputStream(tarGZipIs));
             TarArchiveInputStream tarInputStream = new TarArchiveInputStream(gZipIs)) {

            TarArchiveEntry tarArchiveEntry;
            while ((tarArchiveEntry = tarInputStream.getNextTarEntry()) != null) {
                if (tarArchiveEntry.isFile()) {
                    log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                    if (extract) { //extract
                        if (copyTarEntryToDirectory(outputDir, tarInputStream, tarArchiveEntry, gZipIs,
                                filesToExtract)) {

                            result.add(tarArchiveEntry);
                        }
                    } else { //list
                        result.add(tarArchiveEntry);
                    }
                } else {
                    log.info("Ignored non-regular file {}", tarArchiveEntry.getFile());
                }
            }
        }

        return result;
    }

    /**
     *
     * @param outputDir output directory where files are extracted
     * @param tarInputStream tar InputStream to process
     * @param tarArchiveEntry TarArchiveEntry read from TarArchiveInputStream and currently under processing
     * @param gZipStatistics
     * @param filesToExtract if not null, extract specified files otherwise all files
     * @return tarArchiveEntry was extracted
     * @throws IOException if an I/O error has occurred
     */
    private static boolean copyTarEntryToDirectory(Path outputDir,
                                                   TarArchiveInputStream tarInputStream,
                                                   TarArchiveEntry tarArchiveEntry,
                                                   InputStreamStatistics gZipStatistics,
                                                   List<String> filesToExtract)
            throws IOException {

        if (((filesToExtract != null) && !filesToExtract.isEmpty())) {
            if (filesToExtract.contains(tarArchiveEntry.getName())) {
                copyTarEntryToDirectory(outputDir, tarInputStream, tarArchiveEntry, gZipStatistics);
                return true;
            }
        } else { // extract all
            copyTarEntryToDirectory(outputDir, tarInputStream, tarArchiveEntry, gZipStatistics);
            return true;
        }

        return false;
    }

    private static long copyTarEntryToDirectory(Path outputDir, TarArchiveInputStream tarInputStream,
                                                TarArchiveEntry tarArchiveEntry, InputStreamStatistics gZipStatistics)
            throws IOException {

        Path tarPath = Path.of(tarArchiveEntry.getName());
        log.debug("basename {}", tarPath.getFileName());
        Path newPath = Path.of(outputDir.toString()).resolve(tarPath.getFileName());




//        if (Files.exists(newPath)) {
//
//        }

        double maxUsedPercentage = DEFAULT_MAX_USED_PERCENTAGE;
        if (System.getProperties().containsKey("ee.cyber.cdoc20.maxDiskUsagePercentage")) {
            String maxDiskUsagePercentageStr = System.getProperty("ee.cyber.cdoc20.maxDiskUsagePercentage");
            try {
                maxUsedPercentage = Double.parseDouble(maxDiskUsagePercentageStr);
            } catch (NumberFormatException nfe) {
                log.warn("Invalid value {} for ee.cyber.cdoc20.maxDiskUsagePercentage", maxDiskUsagePercentageStr);
            }
        }



        long written = 0;
        // truncate and overwrite an existing file, or create the file if
        // it doesn't initially exist
        try (OutputStream out = Files.newOutputStream(newPath)) {
            byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = tarInputStream.read(buffer, 0, DEFAULT_BUFFER_SIZE)) >= 0) {

                double usedPercentage = (double)outputDir.toFile().getUsableSpace()
                        / (double)outputDir.toFile().getTotalSpace() * 100;

                if (usedPercentage >= maxUsedPercentage) {
                    String err = String.format("More than  %.2f%% disk space used. Aborting", maxUsedPercentage);
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




        //long written = Files.copy(tarInputStream, newPath, StandardCopyOption.REPLACE_EXISTING);
        log.debug("Created {} {}B", newPath, written);
        return written;
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
