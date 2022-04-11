package ee.cyber.cdoc20.container;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.*;
import static org.junit.jupiter.api.Assertions.*;

class TarGzTest {
    private static final  Logger log = LoggerFactory.getLogger(TarGzTest.class);

    private final File tarGZipFile = new File(System.getProperty("java.io.tmpdir"), "testCreateArchive.tgz");

    private final String payload = "payload\n";


    void deleteDirRecursively(Path dir) throws IOException {
        if (Files.exists(dir)) { //delete dir recursively
            //noinspection ResultOfMethodCallIgnored
            Files.walk(dir)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }

    //@Test
    void testCreateArchive() throws IOException {
        File payloadFile = new File(System.getProperty("java.io.tmpdir"), "payload.txt");
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payload.getBytes(UTF_8));
        }

        File readmeFile = new File("../README.md"); //cdoc20-lib
        if (!readmeFile.exists()) {
            readmeFile = new File("README.md"); // parent dir
        }
        boolean isFile = readmeFile.isFile();

        //File outTarFile = new File(System.getProperty("java.io.tmpdir"), "testCreateArchive.tgz");

        log.debug("Creating tar {}", tarGZipFile);
        try (FileOutputStream fos = new FileOutputStream(tarGZipFile)) {
            tarGZipFile.deleteOnExit();
            Tar.archiveFiles(fos, List.of(payloadFile, readmeFile));
        }

        Set<String> entries = new HashSet<>();

        try (TarArchiveInputStream tar = new TarArchiveInputStream(new GZIPInputStream(new BufferedInputStream(
                new FileInputStream(tarGZipFile))))) {

            TarArchiveEntry entry;
            while ((entry = tar.getNextTarEntry()) != null) {
                entries.add(entry.getName());
            }
        }

        assertEquals(Set.of("payload.txt", "README.md"), entries);
    }

    @Test
    void testExtract() throws IOException {
        testCreateArchive(); //create archive

        Path outDir = Path.of(System.getProperty("java.io.tmpdir")).resolve("testExtract");
        if (Files.exists(outDir)) { //delete tartest dir recursively
            //noinspection ResultOfMethodCallIgnored
            Files.walk(outDir)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }

        Files.createDirectories(outDir);

        log.debug("Extracting {} to {}", tarGZipFile, outDir);
        try (FileInputStream fis = new FileInputStream(tarGZipFile)) {
            Tar.extractToDir(fis, outDir);
        }

        Set<String> extractedFiles;
        try (Stream<Path> stream = Files.list(outDir)) {
            extractedFiles = stream
                    .filter(file -> !Files.isDirectory(file))
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .collect(Collectors.toSet());
        }

        assertEquals(Set.of("payload.txt", "README.md"), extractedFiles);

        Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), "payload.txt");

        String read = Files.readString(payloadPath);

        assertEquals(payload, read);

        if (Files.exists(outDir)) { //delete tartest dir recursively
            //noinspection ResultOfMethodCallIgnored
            Files.walk(outDir)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }

    @Test
    void testArchiveData() throws IOException {
        Path outFile = Path.of(System.getProperty("java.io.tmpdir")).resolve("testArchiveData.tar.gz");
        outFile.toFile().deleteOnExit();

        //Files.deleteIfExists(outFile);

        String tarEntryName = "payload-" + UUID.randomUUID();
        Path payloadPath = Path.of(System.getProperty("java.io.tmpdir")).resolve(tarEntryName);
        payloadPath.toFile().deleteOnExit();

        try (FileOutputStream fos = new FileOutputStream(outFile.toFile())) {
            //Tar.archiveData(fos, payload.getBytes(StandardCharsets.UTF_8), tarEntryName);
            ByteArrayInputStream bos = new ByteArrayInputStream(payload.getBytes(UTF_8));
            Tar.archiveData(fos, bos, tarEntryName);
        }

        try (FileInputStream is = new FileInputStream(outFile.toFile())) {
            List<String> filesList = Tar.listFiles(is);
            assertEquals(List.of(tarEntryName), filesList);
        }

        try (FileInputStream is = new FileInputStream(outFile.toFile());
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            long extractedLen = Tar.extractTarEntry(is, bos, tarEntryName);
            assertTrue(extractedLen > 0);
            assertEquals(payload, bos.toString(UTF_8));
        }
    }

    @Test
    void testTarGzBomb() throws IOException {
        byte[] zeros = new byte[1024];//1KB

        long bigFileSize = 1024 //1KB
                *1024 //1MB
                //*1024 //1GB
                ;

        Path bombPath =  Path.of(System.getProperty("java.io.tmpdir")).resolve("bomb.tgz");
        bombPath.toFile().deleteOnExit();

        try (TarArchiveOutputStream tarOs = new TarArchiveOutputStream(new GZIPOutputStream(new BufferedOutputStream(
                Files.newOutputStream(bombPath))))) {
            tarOs.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            tarOs.setAddPaxHeadersForNonAsciiNames(true);
            TarArchiveEntry tarEntry = new TarArchiveEntry("A");
            tarEntry.setSize(bigFileSize);
            tarOs.putArchiveEntry(tarEntry);

            long written = 0;
            while (written < bigFileSize) {
                tarOs.write(zeros);
                written += zeros.length;
                if (written % (1024*1024) == 0) {
                    log.debug("Wrote {}MB", written / (1024*1024));
                }
            }

            log.debug("Wrote {}B", written);
            tarOs.closeArchiveEntry();
        }


        Path outDir = Path.of(System.getProperty("java.io.tmpdir")).resolve("testTarGzBomb");
        deleteDirRecursively(outDir);
        Files.createDirectories(outDir);

        log.debug("Extracting {} to {}", bombPath, outDir);
        Exception exception = assertThrows(IllegalStateException.class, () -> {
            try (InputStream is = Files.newInputStream(bombPath)) {
                Tar.extractToDir(is, outDir);
            }
        });

        log.debug("Got {} with message: {}", exception.getClass().getName(), exception.getMessage());
        log.debug("Cleaning up {}", outDir);
        deleteDirRecursively(outDir);
    }
}
