package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.utils.InputStreamStatistics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;

/**
 * AutoCloseable tarDeflate stream extractor. If any exception is thrown
 * during processing {@link #process(Path, List, boolean)}, then close() deletes extracted files.
 */
public class TarDeflate implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(TarDeflate.class);

    private DeflateCompressorInputStream zLibIs;
    private TarArchiveInputStream tarIs;

    private List<File> createdFiles = new LinkedList<>();
    private Exception exception;

    /**
     *
     * @param tarDeflateIs tar compressed with deflate
     */
    public TarDeflate(InputStream tarDeflateIs) {
        zLibIs = new DeflateCompressorInputStream(new BufferedInputStream(tarDeflateIs));
        tarIs = new TarArchiveInputStream(zLibIs);
    }

    public List<ArchiveEntry> extractToDir(Path outputDir) throws IOException {
        return process(outputDir, null, true);
    }

    /**
     * Process deflate/zlib compressed tar stream.
     * @param outputDir output directory where files are extracted when extract=true
     * @param filesToExtract extract specified files otherwise (filesToExtract=null) all files.
     *                       No effect for files not present in the container.
     *                       No effect for list (extract=false)
     * @param extract if true, copy extracted files to outputDir. Otherwise, list entries found from the stream
     * @return List<ArchiveEntry> list of TarArchiveEntry processed from stream (ignored entries are not
     *      returned)
     */
    public List<ArchiveEntry> process(@Nullable Path outputDir, @Nullable List<String> filesToExtract, boolean extract)
            throws IOException {

        try {
            return doProcess(outputDir, filesToExtract, extract);
        } catch (Exception ex) {
            exception = ex;
            throw ex;
        }
    }

    /**
     * Process tar/deflate stream. Close tarDeflateIs when stream is processed or exception is thrown. If process result
     * an exception and files were extracted to output directory, then those files are deleted automatically.
     * @param tarDeflateIs InputStream to process
     * @param outputDir output directory where files are extracted when extract=true
     * @param filesToExtract extract specified files otherwise (filesToExtract=null) all files.
     *                       No effect for files not present in the container.
     *                       No effect for list (extract=false)
     * @param extract if true, copy extracted files to outputDir. Otherwise, list entries found from the stream
     * @return List<ArchiveEntry> list of TarArchiveEntry processed from stream (ignored entries are not
     *      returned)
     * @throws IOException if an I/O error has occurred
     */
    public static List<ArchiveEntry> process(InputStream tarDeflateIs,
                   @Nullable Path outputDir, @Nullable List<String> filesToExtract, boolean extract)
            throws IOException {

        try (TarDeflate tar = new TarDeflate(tarDeflateIs)) {
            return tar.process(outputDir, filesToExtract, extract);
        }
    }

    /**
     * Process tar/deflate stream. Close tarDeflateIs when stream is processed or exception is thrown.
     * @param tarDeflateStream InputStream to process
     * @return list of file names found from the tarDeflateStream
     * @throws IOException if an I/O error has occurred
     */
    public static List<String> listFiles(InputStream tarDeflateStream) throws IOException {
        return process(tarDeflateStream, null, null, false).stream()
                .map(ArchiveEntry::getName)
                .toList();
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

        if (!Tar.isOverWriteAllowed() && Files.exists(newPath)) {
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
     * @param gZipStatistics InputStreamStatistics from deflate stream
     * @return File size created
     * @throws IOException if an I/O error has occurred
     */
    private static long copyTarEntryToFile(Path destPath, TarArchiveInputStream tarInputStream,
                                   TarArchiveEntry tarArchiveEntry, InputStreamStatistics gZipStatistics)
            throws IOException {

        double diskUsageThreshold = Tar.getDiskUsedPercentageThreshold();
        long written = 0;
        // truncate and overwrite an existing file, or create the file if
        // it doesn't initially exist
        try (OutputStream out = Files.newOutputStream(destPath)) {
            byte[] buffer = new byte[Tar.DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = tarInputStream.read(buffer, 0, Tar.DEFAULT_BUFFER_SIZE)) >= 0) {

                double usedPercentage = (double)destPath.toFile().getUsableSpace()
                        / (double)destPath.toFile().getTotalSpace() * 100;

                if (usedPercentage >= diskUsageThreshold) {
                    String err = String.format("More than  %.2f%% disk space used. Aborting", diskUsageThreshold);
                    log.error(err);
                    throw new IllegalStateException(err);
                }

                out.write(buffer, 0, read);
                written += read;

                double compressionRatioThreshold = Tar.getCompressionRatioThreshold();
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

    /**
     * Process tar deflate input stream and find entries in it. If extract is true, then files found from inputStream
     * are copied to outputDir.
     * @param outputDir output directory where files are extracted when extract=true
     * @param filesToExtract extract specified files otherwise (filesToExtract=null) all files.
     *                       No effect for files not present in the container.
     *                       No effect for list (extract=false)
     * @param extract if true, extract files to outputDir. Otherwise, list TarArchiveEntries
     * @return List<ArchiveEntry> list of TarArchiveEntry processed in tarGZipInputStream (ignored entries are not
     *      returned)
     * @throws IOException if an I/O error has occurred
     */
    private List<ArchiveEntry> doProcess(@Nullable Path outputDir, @Nullable List<String> filesToExtract,
                                         boolean extract) throws IOException {

        if (extract && (!Files.isDirectory(outputDir) || !Files.isWritable(outputDir))) {
            throw new IOException("Not directory or not writeable " + outputDir);
        }

        if (extract) {
            log.info("Extracting to {}", outputDir.normalize());
        }

        List<ArchiveEntry> extractedArchiveEntries = new LinkedList<>();

        int tarEntriesThreshold = Tar.getTarEntriesThresholdThreshold();
        TarArchiveEntry tarArchiveEntry;
        while ((tarArchiveEntry = tarIs.getNextTarEntry()) != null) {

            if (tarArchiveEntry.isFile()) {
                log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                //extract
                if (extract && ((filesToExtract == null) || filesToExtract.contains(tarArchiveEntry.getName()))) {

                    Path destPath = pathFromTarEntry(outputDir, tarArchiveEntry, true);
                    createdFiles.add(destPath.toFile());
                    copyTarEntryToFile(destPath, tarIs, tarArchiveEntry, zLibIs);

                    extractedArchiveEntries.add(tarArchiveEntry);
                    if (extractedArchiveEntries.size() > tarEntriesThreshold) {
                        log.error("Tar entries threshold ({}) exceeded.", tarEntriesThreshold);
                        throw new IllegalStateException("Tar entries threshold exceeded. Aborting.");
                    }
                } else { //list
                    extractedArchiveEntries.add(tarArchiveEntry);
                }
            } else {
                log.error("tar contained non-regular file {}", tarArchiveEntry.getName());
                throw new IOException("Tar entry with illegal type found");
            }
        }

        log.debug("Uncompressed {}B from {}B (compressed)",
                zLibIs.getUncompressedCount(), zLibIs.getCompressedCount());

        // TarArchive processing is finished after first zero block is encountered. Adding additional data after that
        // block makes possible to "hide" additional data after tar archive. This may be attempt to disable
        // MAC checking as not all data won't be processed. Suspicious.
        if (zLibIs.available() > 0) {
            log.warn("Unexpected data after tar {}B.", zLibIs.available());
            throw new IOException("Unexpected data after tar");
        }

        return extractedArchiveEntries;
    }

    /**
     * Delete files created during process()
     * @param filesToDelete
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
     * If there was exception during processing and files were extracted from tar deflate stream, then deletes files
     * extracted from tar deflate stream
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (log.isDebugEnabled()) {
            String exStr = (exception == null) ? "" : "exception \"" + exception + "\", ";
            log.debug("TarDeflate::close() {} created files: {}", exStr, createdFiles.size());
        }
        if ((exception != null) && !createdFiles.isEmpty()) {
            deleteFiles(createdFiles);
        }
        tarIs.close();
        zLibIs.close();
    }
}
