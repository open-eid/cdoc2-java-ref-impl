package ee.cyber.cdoc20.container;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Utility class for dealing with tar gz stream/files. Only supports regular files inside tar.
 */
public class Tar {

    private final static Logger log = LoggerFactory.getLogger(Tar.class);

    private Tar() {
    }

    static void addFileToTar(TarArchiveOutputStream tarArchiveOutputStream, Path file, String entryName)
            throws IOException {

        log.debug("Adding file {} as {}", file.toAbsolutePath(), entryName);
        if (Files.isRegularFile(file)) {
            TarArchiveEntry tarArchiveEntry = (TarArchiveEntry) tarArchiveOutputStream.createArchiveEntry(file.toFile(),
                    entryName);

//            if (file.toFile().canExecute()) {
//                //tarArchiveEntry.setMode(tarArchiveEntry.getMode() | 0755);
//            }
            tarArchiveOutputStream.putArchiveEntry(tarArchiveEntry);

            try (InputStream input = new BufferedInputStream(Files.newInputStream(file))) {
                long written = input.transferTo(tarArchiveOutputStream);
                log.debug("Added {}B", written);
            }
        } else {
            throw new IOException("Not a file: "+file);
        }
        tarArchiveOutputStream.closeArchiveEntry();
    }

    public static void archiveFiles(OutputStream dest, Iterable<File> files)
            throws IOException {
        //File tarFile = new File(FileUtils.getTempDirectoryPath(), archiveNameWithOutExtension + ".tar");
        //tarFile.deleteOnExit();
        try (TarArchiveOutputStream tos = new TarArchiveOutputStream(new GZIPOutputStream(new BufferedOutputStream(
                dest)))) {
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
     * @param data data added to archive
     * @param tarEntryName entry name (file name) for data
     * @throws IOException
     */
    public static void archiveData(OutputStream dest, byte[] data, String tarEntryName) throws IOException{
        try (TarArchiveOutputStream tos = new TarArchiveOutputStream(new GZIPOutputStream(new BufferedOutputStream(
                dest)))) {
            tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            TarArchiveEntry tarEntry = new TarArchiveEntry(tarEntryName);
            tarEntry.setSize(data.length);
            tos.putArchiveEntry(tarEntry);

            tos.write(data, 0, data.length);
            tos.closeArchiveEntry();
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
            throws IOException{

        try (TarArchiveInputStream tarInputStream = new TarArchiveInputStream(new GZIPInputStream(
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
     * @param tarGZipInputStream tar gzip InputStream to process
     * @param outputDir output directory where files are extracted when extract=true
     * @param extract if true, extract files to outputDir. Otherwise list TarArchiveEntries
     * @return List<ArchiveEntry> list of TarArchiveEntry found in tarGZipInputStream
     * @throws IOException if an I/O error has occurred
     */
    static List<ArchiveEntry> processTarGz(InputStream tarGZipInputStream, Path outputDir, boolean extract) throws IOException {

        if (extract && (!Files.isDirectory(outputDir) || !Files.isWritable(outputDir))) {
            throw new IOException("Not directory or not writeable "+ outputDir);
        }

        LinkedList<ArchiveEntry> result = new LinkedList<>();
        try (TarArchiveInputStream tarInputStream = new TarArchiveInputStream(new GZIPInputStream(
                new BufferedInputStream(tarGZipInputStream)))) {

            TarArchiveEntry tarArchiveEntry;
            while ((tarArchiveEntry = tarInputStream.getNextTarEntry()) != null) {
                if (tarArchiveEntry.isFile()) {
                    log.debug("Found: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                    if (extract) {
                        Path newPath = Paths.get(outputDir.toString(), tarArchiveEntry.getName());
                        long written = Files.copy(tarInputStream, newPath, StandardCopyOption.REPLACE_EXISTING);
                        log.debug("Created {} {}B", newPath, written);
                    }
                    result.add(tarArchiveEntry);
                } else {
                    log.info("Ignored non-regular file {}", tarArchiveEntry.getFile());
                }
            }
        }

        return result;
    }

    public static List<ArchiveEntry> extractToDir(InputStream tarGZipInputStream, Path outputDir) throws IOException {
        return processTarGz(tarGZipInputStream, outputDir, true);
    }

    public static List<ArchiveEntry> listEntries(InputStream tarGZipInputStream) throws IOException {
        return processTarGz(tarGZipInputStream, null, false);
    }

    public static List<String> listFiles(InputStream tarGZipInputStream) throws IOException {
        return processTarGz(tarGZipInputStream, null, false).stream()
                .map(ArchiveEntry::getName)
                .collect(Collectors.toList());
    }
}
