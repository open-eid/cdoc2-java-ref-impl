package ee.cyber.cdoc2.converter;

import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.converter.util.PasswordCheckUtil;
import ee.cyber.cdoc2.converter.util.Util;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.token.pkcs12.PKCS12Token;
import org.openeid.cdoc4j.token.pkcs12.exception.PKCS12Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConverterTest {

    Logger log = LoggerFactory.getLogger(ConverterTest.class);

    // cdoc4j sample files from https://github.com/open-eid/cdoc4j/tree/master/src/test/resources
    static final String CDOC_FILE = "src/test/resources/cdoc/valid_cdoc11_ECC.cdoc";
    static final String ECC_P12 = "src/test/resources/ecc/ecc.p12";

    // password for ECC_P12
    static final String ECC_P12_PW = "test";

    // password used to derive bytes for re-encryption
    static final char[] CDOC2_TEST_PW = {'T', 'e', 's', 't', ' ', 'p', 'w', 'd', '2'};

    // cdoc2 requires label with password
    public static final String CDOC2_TEST_LABEL = "pw_label";

    @Test
    void testPwnedPasswd() throws Exception {
        assertTrue(PasswordCheckUtil.isPwned("password".toCharArray()));
        assertTrue(PasswordCheckUtil.isPwned("012345678".toCharArray()));
        assertFalse(PasswordCheckUtil.isPwned("b1g_Apple!".toCharArray()));
    }

    @Test
    void testReEncrypt(@TempDir Path tempDir) throws Exception {

        Path outCdoc2 = tempDir.resolve("testReEncrypt.out.cdoc2");

        Path outCdoc2Dir = tempDir.resolve("decrypted");
        assertTrue(outCdoc2Dir.toFile().mkdir());

        try (InputStream cdocIs = Files.newInputStream(Path.of(CDOC_FILE))) {

            Util.reEncrypt(cdocIs, getTestToken(),
                outCdoc2.toFile(), CDOC2_TEST_LABEL, CDOC2_TEST_PW,
                tempDir);
        }

        List<String> extractedFiles = new CDocDecrypter()
            .withCDoc(outCdoc2.toFile())
            .withRecipient(DecryptionKeyMaterial.fromPassword(CDOC2_TEST_PW, CDOC2_TEST_LABEL))
            .withDestinationDirectory(outCdoc2Dir.toFile())
            .decrypt();

        assertEquals(1, extractedFiles.size());
        assertEquals("lorem1.txt", extractedFiles.get(0));
        Path fileOne =  outCdoc2Dir.resolve(extractedFiles.get(0));
        assertEquals("lorem ipsum", Files.readString(fileOne));
    }

    @Test
    void testSignedAsicContainerEncrypt(@TempDir Path tempDir) throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File asicFile = new File(classLoader.getResource("asic/signed.asice").getFile());
        handleAsicFilesForEncryption(List.of(asicFile), tempDir);
    }

    @Test
    void testNotSignedAsicContainerEncrypt(@TempDir Path tempDir) throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File asicFile = new File(classLoader.getResource("asic/no-signature.asice").getFile());
        Container container = ContainerOpener.open(asicFile.getPath());
        List<File> extractedFiles = checkSignatureOrExtractFiles(container, asicFile);
        handleAsicFilesForEncryption(extractedFiles, tempDir);
    }

    static Token getTestToken() throws FileNotFoundException, PKCS12Exception {
        return new PKCS12Token(new FileInputStream(ECC_P12), ECC_P12_PW);
    }

    private void handleAsicFilesForEncryption(List<File> files, Path tempDir) throws Exception {
        Path outCdoc2 = tempDir.resolve("testAsicEncrypt.out.cdoc2");

        Util.encrypt(outCdoc2.toFile(), files, CDOC2_TEST_LABEL, CDOC2_TEST_PW);

        Path outCdoc2Dir = tempDir.resolve("decrypted");
        assertTrue(outCdoc2Dir.toFile().mkdir());

        List<String> extractedFiles = new CDocDecrypter()
            .withCDoc(outCdoc2.toFile())
            .withRecipient(DecryptionKeyMaterial.fromPassword(CDOC2_TEST_PW, CDOC2_TEST_LABEL))
            .withDestinationDirectory(outCdoc2Dir.toFile())
            .decrypt();

        assertEquals(1, extractedFiles.size());
        assertEquals(files.get(0).getName(), extractedFiles.get(0));
    }

    private List<File> checkSignatureOrExtractFiles(
        Container container,
        File incomingFile
    ) {
        if (!container.getSignatures().isEmpty()) {
            return List.of(incomingFile);
        } else {
            List<DataFile> dataFiles = container.getDataFiles();
            List<File> extractedFiles = new ArrayList<>();
            for (DataFile dataFile : dataFiles) {
                String incomingFilePath = incomingFile.getPath();
                String outFilePath =
                    incomingFilePath.substring(0, incomingFilePath.lastIndexOf("/") + 1);
                String extractedFile = outFilePath + "/" + dataFile.getName();
                dataFile.saveAs(extractedFile);
                extractedFiles.add(new File(extractedFile));
            }
            return extractedFiles;
        }
    }
}
