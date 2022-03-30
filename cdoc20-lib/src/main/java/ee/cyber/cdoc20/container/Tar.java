package ee.cyber.cdoc20.container;

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

            if (file.toFile().canExecute()) {
                //tarArchiveEntry.setMode(tarArchiveEntry.getMode() | 0755);
            }
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

    static List<TarArchiveEntry> processTarGz(InputStream tarGZipInputStream, Path outputDir, boolean extract) throws IOException {

        if (extract && (!Files.isDirectory(outputDir) || !Files.isWritable(outputDir))) {
            throw new IOException("Not directory or not writeable "+ outputDir);
        }

        LinkedList<TarArchiveEntry> result = new LinkedList<>();

        try (TarArchiveInputStream tarInputStream = new TarArchiveInputStream(new GZIPInputStream(new BufferedInputStream(
                tarGZipInputStream)))) {
            TarArchiveEntry tarArchiveEntry;
            while ((tarArchiveEntry = tarInputStream.getNextTarEntry()) != null) {
                if (tarArchiveEntry.isFile()) {
                    log.debug("Extracting: {} {}B", tarArchiveEntry.getName(), tarArchiveEntry.getSize());
                    Path newPath = Paths.get(outputDir.toString(), tarArchiveEntry.getName());
                    if (extract) {
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

    public static List<TarArchiveEntry> extractToDir(InputStream tarGZipInputStream, Path outputDir) throws IOException {
        return processTarGz(tarGZipInputStream, outputDir, true);
    }

    public static List<TarArchiveEntry> listEntries(InputStream tarGZipInputStream) throws IOException {
        return processTarGz(tarGZipInputStream, null, false);
    }

    public static List<String> listFiles(InputStream tarGZipInputStream) throws IOException {
        return processTarGz(tarGZipInputStream, null, false).stream()
                .map(TarArchiveEntry::getName)
                .collect(Collectors.toList());
    }
}
