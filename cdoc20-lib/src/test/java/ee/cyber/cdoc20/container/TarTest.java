package ee.cyber.cdoc20.container;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarFile;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TarTest {
    private final static Logger log = LoggerFactory.getLogger(TarTest.class);

    private final File tarGZipFile = new File(System.getProperty("java.io.tmpdir"), "testCreateArchive.tgz");

    private final String payload = "payload\n";

    //@Test
    void testCreateArchive() throws IOException{
        File payloadFile = new File(System.getProperty("java.io.tmpdir"), "payload.txt");
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        File readmeFile = new File("../README.md"); //cdoc20-lib
        if (!readmeFile.exists()) {
            readmeFile = new File("README.md"); // parent dir
        }
        boolean isFile = readmeFile.isFile();

        //File outTarFile = new File(System.getProperty("java.io.tmpdir"), "testCreateArchive.tgz");

        log.debug("Creating tar {}", tarGZipFile);
        try (FileOutputStream fos = new FileOutputStream(tarGZipFile)) {
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
    public void testExtract() throws IOException {
        testCreateArchive(); //create archive

        Path outDir = Path.of(System.getProperty("java.io.tmpdir")).resolve( "tartest");
        if (Files.exists(outDir)) { //delete tartest recursively
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

        Path payload_txt = Path.of(outDir.toAbsolutePath().toString(), "payload.txt");

        String read = Files.readString(payload_txt);

        assertEquals(payload, read);
    }
}