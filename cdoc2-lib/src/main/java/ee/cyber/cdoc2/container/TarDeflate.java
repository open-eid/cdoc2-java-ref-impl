package ee.cyber.cdoc2.container;

import ee.cyber.cdoc2.CDocConfiguration;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.utils.InputStreamStatistics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;

/**
 * AutoCloseable tarDeflate stream extractor. If any exception is thrown
 * during processing {@link #process(TarEntryProcessingDelegate)}, then close() deletes extracted files.
 */
public class TarDeflate implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(TarDeflate.class);

    /**
     * Created from Cha Cha input stream and used for reading compressed data.
     */
    private final DeflateCompressorInputStream zLibIs;

    /**
     * Created from ZLib input stream and used for reading compressed tar archive.
     */
    private final TarArchiveInputStream tarIs;

    /**
     * Files extracted from tar deflate stream within decryption.
     */
    private final List<File> createdFiles = new LinkedList<>();

    /**
     * Exception that occurred during stream processing.
     * Helps to control and delete extracted files from tar deflate stream, in case of
     * process failure.
     */
    private Exception exception;

    /**
     *
     * @param tarDeflateIs tar compressed with deflate
     */
    public TarDeflate(InputStream tarDeflateIs) {
        zLibIs = new DeflateCompressorInputStream(new BufferedInputStream(tarDeflateIs));
        tarIs = new TarArchiveInputStream(zLibIs);
    }

    /**
     * Extract all files from underlying archive to directory
     * @param outputDir ouputDir
     * @return files extracted
     * @throws IOException
     */
    public List<ArchiveEntry> extractToDir(Path outputDir) throws IOException {
            return process(new ExtractDelegate(outputDir, null));
    }

    /**
     * Extract files from underlying archive to directory
     * @param filesToExtract  files to extract
     * @param outputDir outputDir
     * @return files extracted
     * @throws IOException
     */
    public List<ArchiveEntry> extractFilesToDir(List<String> filesToExtract, Path outputDir)
        throws IOException {

        return process(new ExtractDelegate(outputDir, filesToExtract));
    }

    /**
     * Process tar/deflate stream. Close tarDeflateIs when stream is processed or exception is thrown.
     * @param tarDeflateStreamIs InputStream to process
     * @return list of file names found from the tarDeflateStream
     * @throws IOException if an I/O error has occurred
     */
    public static List<String> listFiles(InputStream tarDeflateStreamIs) throws IOException {
        try (TarDeflate tar = new TarDeflate(tarDeflateStreamIs)) {
            return tar.process(new ListDelegate()).stream()
                .map(ArchiveEntry::getName)
                .toList();
        }
    }

    /**
     * Process archive
     * @param tarEntryProcessingDelegate processing to be done with archive. Contains output type specific parameters
     * @return ArchiveEntries processed
     * @throws IOException if an I/O error has occurred
     */
    public List<ArchiveEntry> process(
        TarEntryProcessingDelegate tarEntryProcessingDelegate
    ) throws IOException {

        // wrap doProcess to record any thrown exception,
        // so that close() can delete created files or do other clean up when exception was thrown
        try {
            return doProcess(tarEntryProcessingDelegate);
        } catch (Exception ex) {
            exception = ex;
            throw ex;
        }
    }

    /**
     * Process tar deflate input stream and find entries in it. Process entries based on operation:
     * @param delegate TarEntryProcessingDelegate used to process tar entries in tar input stream
     * @return List<ArchiveEntry> list of TarArchiveEntry processed in tarGZipInputStream (ignored entries are not
     *      returned)
     * @throws IOException if an I/O error has occurred
     */
    private List<ArchiveEntry> doProcess(
        TarEntryProcessingDelegate delegate
    ) throws IOException {

        if (delegate.getType() == TarEntryProcessingDelegate.OP.EXTRACT) {
            log.info("Extracting to {}", delegate.getOutputDir().toPath().normalize());
        }

        List<ArchiveEntry> processedArchiveEntries = new LinkedList<>();

        int tarEntriesThreshold = Tar.getTarEntriesThresholdThreshold();
        TarArchiveEntry tarArchiveEntry;
        while ((tarArchiveEntry = tarIs.getNextEntry()) != null) {

            checkExistingTarEntryName(processedArchiveEntries, tarArchiveEntry);

            if (processTarEntry(delegate, tarArchiveEntry, tarIs, zLibIs)) {
                processedArchiveEntries.add(tarArchiveEntry);
            }

            checkTarEntriesThreshold(processedArchiveEntries, tarEntriesThreshold);
        }

        log.debug("Uncompressed {}B from {}B (compressed)",
            zLibIs.getUncompressedCount(), zLibIs.getCompressedCount());

        checkUnExpectedDataAfterTar();

        return processedArchiveEntries;
    }

    /**
     * Check whether entries in archive threshold has exceeded. Throws exception, when threshold has been exceeded.
     * @param processedArchiveEntries entries already processed
     * @param tarEntriesThreshold threshold to check
     */
    private static void checkTarEntriesThreshold(List<ArchiveEntry> processedArchiveEntries, int tarEntriesThreshold) {
        if (processedArchiveEntries.size() > tarEntriesThreshold) {
            log.error("Tar entries threshold ({}) exceeded.", tarEntriesThreshold);
            throw new IllegalStateException("Tar entries threshold exceeded. Aborting.");
        }
    }

    /**
     * Throws exception if archive entry with the same name is already part of processedArchiveEntries.
     * @param processedArchiveEntries list containing entries that have already been processed
     * @param tarArchiveEntry archive entry to check
     * @throws IOException
     */
    private static void checkExistingTarEntryName(List<ArchiveEntry> processedArchiveEntries,
                                                  TarArchiveEntry tarArchiveEntry
    ) throws IOException {
        if (processedArchiveEntries.stream()
            .map(ArchiveEntry::getName)
            .toList()
            .contains(tarArchiveEntry.getName())) {
            throw new IOException("Duplicate tar entry name found: " + tarArchiveEntry.getName());
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
    public static Path pathFromTarEntry(Path outputDir, TarArchiveEntry tarArchiveEntry, boolean createFile)
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

        if (!CDocConfiguration.isOverWriteAllowed() && Files.exists(newPath)) {
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
     * Process tarEntry.
     * @param delegate TarEntryProcessing that is used for tarArchiveEntry processing
     * @param fromTarInputStream tar input stream currently processed
     * @param inputStreamStatistics InputStreamStatistics that wraps fromTarInputStream
     * @return if tarArchiveEntry was processed. If false and no exception, then tarArchive was ignored.
     * @throws IOException if an I/O error occurs
     */
    private boolean processTarEntry(
                                  TarEntryProcessingDelegate delegate,
                                  TarArchiveEntry tarArchiveEntry,
                                  TarArchiveInputStream fromTarInputStream,
                                  InputStreamStatistics inputStreamStatistics
    ) throws IOException {

        double diskUsageThreshold = Tar.getDiskUsedPercentageThreshold();
        long written = 0;
        boolean processed;

        if (tarArchiveEntry.isFile()) {
            log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());

            File createdFile = delegate.onTarEntry(tarArchiveEntry);
            if (createdFile != null) {
                createdFiles.add(createdFile);
            }

            byte[] buffer = new byte[Tar.DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = fromTarInputStream.read(buffer, 0, Tar.DEFAULT_BUFFER_SIZE)) >= 0) {

                //check available disk space
                checkAvailableDiskSpace(delegate.getOutputDir(), diskUsageThreshold);

                delegate.write(buffer, 0, read);
                written += read;

                checkCompressionRatioThreshold(tarArchiveEntry, inputStreamStatistics);
            }

            processed = delegate.onEndOfTarEntry();

            log.debug("Transferred {} {}B", tarArchiveEntry.getName(), written);

        } else {
            throw Tar.logTarEntryIllegalTypeAndThrow(tarArchiveEntry.getName());
        }

        return processed;
    }

    /**
     * Throws exception when compression ratio (uncompressed/compressed) is above threshold
     * @param tarArchiveEntry tar entry currently under processing
     * @param isStatistics InputStreamStatistics to use for compression ratio calculation
     */
    private static void checkCompressionRatioThreshold(TarArchiveEntry tarArchiveEntry,
                                                       InputStreamStatistics isStatistics) {
        double compressionRatioThreshold = Tar.getCompressionRatioThreshold();
        double compressionRatio = (double) isStatistics.getUncompressedCount()
            / (double) isStatistics.getCompressedCount();
        if (compressionRatio > compressionRatioThreshold) {
            log.debug("Compression ratio for {} is {}", tarArchiveEntry.getName(), compressionRatio);
            // ratio between compressed and uncompressed data is highly suspicious,
            // looks like a Zip Bomb Attack
            throw new IllegalStateException("Deflate compression ratio " + compressionRatio + " is over "
                + compressionRatioThreshold);
        }
    }

    /**
     * Throws exception when disk usage is above diskUsageThreshold
     * @param destDir directory (and partition) where available disk space is checked
     * @param diskUsageThreshold
     */
    private static void checkAvailableDiskSpace(File destDir, double diskUsageThreshold) {
        if ((destDir != null) && (destDir.exists())) {
            double usedPercentage = (double) destDir.getUsableSpace()
                / (double) destDir.getTotalSpace() * 100;

            if (usedPercentage >= diskUsageThreshold) {
                String err = String.format("More than  %.2f%% disk space used. Aborting", diskUsageThreshold);
                log.error(err);
                throw new IllegalStateException(err);
            }
        }
    }

    /**
     * After tar processing has finished (2 blocks of 0x00 bytes), then deflate will stop processing.
     * Throw exception when there is more bytes after tar end blocks.
     * @throws IOException when bytes are available from deflate stream.
     */
    private void checkUnExpectedDataAfterTar() throws IOException {
        // TarArchive processing is finished after first zero block is encountered. Adding additional data after that
        // block makes possible to "hide" additional data after tar archive. This may be an attempt to disable
        // MAC checking as not all data won't be processed. Suspicious.

        if ((zLibIs.available() > 0)
            && (zLibIs.read() != -1) // DeflateCompressorInputStream.available() sometimes
                                     // incorrectly reports that bytes available for reading,
                                     // check that bytes can actually read
        ) {
            log.warn("Unexpected data after tar {}B.", zLibIs.available());
            throw new IOException("Unexpected data after tar");
        }
    }

    /**
     * Delete files created during process()
     * @param filesToDelete files to be deleted
     */
    private static void deleteFiles(List<File> filesToDelete) {
        log.debug("Deleting {}", filesToDelete);
        for (File f: filesToDelete) {
            try {
                Files.deleteIfExists(f.toPath());
            } catch (IOException e) {
                log.error("Error deleting file {}", f.getAbsolutePath());
            }
        }
    }

    /**
     * Force deletion of extracted files created during process()
     */
    public void deleteCreatedFiles() {
        log.debug("deleteCreatedFiles()");
        deleteFiles(createdFiles);
    }

    /**
     * If there was exception during processing and files were extracted from tar deflate stream,
     * then deletes files extracted from tar deflate stream
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (log.isDebugEnabled()) {
            String exStr = (exception == null) ? "" : "exception \"" + exception + "\", ";

            int countedCreatedFiles = createdFiles.size();
            if (countedCreatedFiles > 0) {
                log.debug("TarDeflate::close() {} created files: {}", exStr, countedCreatedFiles);
            } else {
                log.debug("TarDeflate::close() {}", exStr);
            }
        }
        if ((exception != null) && !createdFiles.isEmpty()) {
            deleteFiles(createdFiles);
        }
        tarIs.close();
        zLibIs.close();
    }

}
