package ee.cyber.cdoc20.container;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ee.cyber.cdoc20.CDocConfiguration;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc20.CDocConfiguration.DISK_USAGE_THRESHOLD_PROPERTY;
import static java.nio.charset.StandardCharsets.*;
import static org.junit.jupiter.api.Assertions.*;

// test are executed sequentially without any other tests running at the same time
@Isolated
class TarGzTest {
    private static final  Logger log = LoggerFactory.getLogger(TarGzTest.class);

    private static final String TGZ_FILE_NAME = "archive.tgz";
    private static final String PAYLOAD = "payload\n";
    private static final List<String> INVALID_FILE_NAMES = List.of(
        "CON", "con", "PRN", "AUX", "aux", "NUL", "nul", "COM2", "LPT1", "com1", "lpt1",
        "abc:", "test ", "test.", "abc>", "abc<", "abc\\",
        "abc|", "abc?", "abc*", "abc\"",
        "test ", "test.", "test\n", "test\t", "-test.text"
    );

    private static final List<String> VALID_FILE_NAMES = List.of("control", "test");

    void testCreateArchive(Path tempDir) throws IOException {
        File payloadFile = tempDir.resolve("payload.txt").toFile();
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(PAYLOAD.getBytes(UTF_8));
        }

        File readmeFile = new File("../README.md"); //cdoc20-lib
        if (!readmeFile.exists()) {
            readmeFile = new File("README.md"); // parent dir
        }

        File tarGZipFile = tempDir.resolve(TGZ_FILE_NAME).toFile();
        log.debug("Creating tar {}", tarGZipFile);
        try (FileOutputStream fos = new FileOutputStream(tarGZipFile)) {
            Tar.archiveFiles(fos, List.of(payloadFile, readmeFile));
        }

        Set<String> entries = new HashSet<>();

        try (TarArchiveInputStream tar = new TarArchiveInputStream(new DeflateCompressorInputStream(
                new BufferedInputStream(new FileInputStream(tarGZipFile))))) {

            TarArchiveEntry entry;
            while ((entry = tar.getNextTarEntry()) != null) {
                entries.add(entry.getName());
            }
        }

        assertEquals(Set.of("payload.txt", "README.md"), entries);
    }

    @Test
    void testExtract(@TempDir Path tempDir) throws IOException {
        testCreateArchive(tempDir); //create archive
        File tarGZipFile = tempDir.resolve(TGZ_FILE_NAME).toFile();

        Path outDir = tempDir.resolve("testExtract");
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

        assertEquals(PAYLOAD, read);
    }

    //TempDir and its contents will be automatically cleaned up by Junit
    @Test
    void testArchiveData(@TempDir Path tempDir) throws IOException {
        Path outFile = tempDir.resolve("testArchiveData.tar.gz");

        String tarEntryName = "payload-" + UUID.randomUUID();

        try (FileOutputStream fos = new FileOutputStream(outFile.toFile())) {
            ByteArrayInputStream bos = new ByteArrayInputStream(PAYLOAD.getBytes(UTF_8));
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
            assertEquals(PAYLOAD, bos.toString(UTF_8));
        }
    }

    @Test
    void testTarGzBomb(@TempDir Path tempDir) throws IOException {
        byte[] zeros = new byte[1024]; //1KB

        long bigFileSize = 1024 //1KB
                * 1024; //1MB
                //*1024 //1GB
                //;

        Path bombPath =  tempDir.resolve("bomb.tgz");
        //bombPath.toFile().deleteOnExit();

        try (TarArchiveOutputStream tarOs = new TarArchiveOutputStream(new DeflateCompressorOutputStream(
                new BufferedOutputStream(Files.newOutputStream(bombPath))))) {
            tarOs.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            tarOs.setAddPaxHeadersForNonAsciiNames(true);
            TarArchiveEntry tarEntry = new TarArchiveEntry("A");
            tarEntry.setSize(bigFileSize);
            tarOs.putArchiveEntry(tarEntry);

            long written = 0;
            while (written < bigFileSize) {
                tarOs.write(zeros);
                written += zeros.length;
                if (written % (1024 * 1024) == 0) {
                    log.debug("Wrote {}MB", written / (1024 * 1024));
                }
            }

            log.debug("Wrote {}B", written);
            tarOs.closeArchiveEntry();
        }


        Path outDir = tempDir.resolve("testTarGzBomb");
        Files.createDirectories(outDir);

        log.debug("Extracting {} to {}", bombPath, outDir);
        Exception exception = assertThrows(IllegalStateException.class, () -> {
            try (InputStream is = Files.newInputStream(bombPath)) {
                Tar.extractToDir(is, outDir);
            }
        });

        log.debug("Got {} with message: {}", exception.getClass().getName(), exception.getMessage());
    }

    @Test
    void testCheckDiskSpaceAvailable(@TempDir Path tempDir) {
        //might cause other tests to fail, if tests executed parallel
        System.setProperty(DISK_USAGE_THRESHOLD_PROPERTY, "0.1");

        assertThrows(IllegalStateException.class, () -> testExtract(tempDir));

        System.clearProperty(DISK_USAGE_THRESHOLD_PROPERTY);
    }

    @Test
    void testMaxExtractEntries(@TempDir Path tempDir) {
        //might cause other tests to fail, if tests executed parallel
        System.setProperty(CDocConfiguration.TAR_ENTRIES_THRESHOLD_PROPERTY, "1");

        assertThrows(IllegalStateException.class, () -> testExtract(tempDir));

        System.clearProperty(CDocConfiguration.TAR_ENTRIES_THRESHOLD_PROPERTY);
    }

    @Test
    void shouldValidateFileNameWhenCreatingTar(@TempDir Path tempDir) throws IOException {
        File outputTarFile = tempDir.resolve(TGZ_FILE_NAME).toFile();

        assertFalse(INVALID_FILE_NAMES.isEmpty());

        // should fail
        for (String fileName: INVALID_FILE_NAMES) {
            File file = createAndWriteToFile(tempDir, fileName, PAYLOAD);
            OutputStream os = new ByteArrayOutputStream();
            assertThrows(
                InvalidPathException.class,
                () -> Tar.archiveFiles(os, List.of(file)),
                "File with name '" + file + "' should not be allowed in created tar"
            );
        }

        // should pass
        for (String fileName: VALID_FILE_NAMES) {
            File file = createAndWriteToFile(tempDir, fileName, PAYLOAD);
            var bos = new ByteArrayOutputStream();
            Tar.archiveFiles(bos, List.of(file));
            assertTrue(bos.toByteArray().length > 0);
        }
    }

    @Test
    void shouldValidateFileNameWhenExtractingTar(@TempDir Path tempDir) throws IOException {
        // should fail
        for (int i = 0; i < INVALID_FILE_NAMES.size(); i++) {
            String fileName = INVALID_FILE_NAMES.get(i);
            File file = createTar(tempDir, TGZ_FILE_NAME + '.' + i, fileName, PAYLOAD);

            assertThrows(
                InvalidPathException.class,
                () -> Tar.processTarGz(new FileInputStream(file), tempDir, List.of(fileName), true),
                "File with name '" + fileName + "' should not be extracted from tar"
            );
        }

        // should pass
        int i = 0;
        for (String fileName: VALID_FILE_NAMES) {
            File file = createTar(tempDir, TGZ_FILE_NAME + '.' + i++, fileName, PAYLOAD);
            var result = Tar.processTarGz(new FileInputStream(file), tempDir, List.of(fileName), true);
            assertTrue(result.size() == 1);
        }
    }

    private static File createAndWriteToFile(Path path, String fileName, String contents) throws IOException {
        File file = path.resolve(fileName).toFile();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(contents.getBytes(UTF_8));
        }
        return file;
    }

    private static File createTar(Path path, String tarFileName, String entryFileName, String entryContents)
            throws IOException {
        File outFile = path.resolve(tarFileName).toFile();

        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            ByteArrayInputStream bos = new ByteArrayInputStream(entryContents.getBytes(UTF_8));
            Tar.archiveData(fos, bos, entryFileName);
        }
        return outFile;
    }

}
