import ee.cyber.cdoc2.cli.CDocCli;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.opentest4j.AssertionFailedError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CDocCliTest {

    private static final Logger log = LoggerFactory.getLogger(CDocCliTest.class);

    private static final String PASSWORD_OPTION = "--password=passwordlabel:myPlainTextPassword";
    private static final String SECRET_OPTION
        = "--secret=label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=";
    private static final int SUCCESSFUL_EXIT_CODE = 0;
    private static final int FAILURE_EXIT_CODE = 1;

    final PrintStream originalOut = System.out;
    final PrintStream originalErr = System.err;
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    @BeforeEach // JUnit 5
    public void setUpStreams() {
        out.reset();
        err.reset();
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));
    }

    @AfterEach // JUnit 5
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    void testCreateDecryptDocEC(@TempDir Path tempPath) throws IOException {
        checkCreateDecryptDocWithPublicKey(tempPath, "keys/bob_pub.pem", "keys/bob.pem");
    }

    @Test
    void testCreateDecryptDocECShort(@TempDir Path tempPath) throws IOException {
        String publicKey = "keys/cdoc2client_pub.pem";
        String privateKey = "keys/cdoc2client.pem";

        checkCreateDecryptDocWithPublicKey(tempPath, publicKey, privateKey);
    }

    @Test
    void testCreateDecryptDocRSA(@TempDir Path tempPath) throws IOException {
        String publicKey = "keys/rsa_pub.pem";
        String privateKey = "keys/rsa_priv.pem";

        checkCreateDecryptDocWithPublicKey(tempPath, publicKey, privateKey);
    }

    @Test
    void testSuccessfulCreateDecryptDocWithPassword(@TempDir Path tempPath) throws IOException {
        checkCreateDecryptDoc(tempPath, PASSWORD_OPTION, PASSWORD_OPTION, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void testSuccessfulCreateDecryptDocWithSecret(@TempDir Path tempPath) throws IOException {
        checkCreateDecryptDoc(tempPath, SECRET_OPTION, SECRET_OPTION, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void failToEncryptDocWhenSecretInPlainText(@TempDir Path tempPath) {
        String secret = "--secret=secretLabel:secretCannotBeInPlainText";
        assertThrowsException(() ->
            checkCreateDecryptDoc(tempPath, secret, secret, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldFailToEncryptDocWithSecretButDecryptWithPassword(@TempDir Path tempPath) {
        assertThrowsException(() ->
            checkCreateDecryptDoc(tempPath, SECRET_OPTION, PASSWORD_OPTION, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldFailToEncryptDocWithPasswordButDecryptWithSecret(@TempDir Path tempPath) {
        assertThrowsException(() ->
            checkCreateDecryptDoc(tempPath, PASSWORD_OPTION, SECRET_OPTION, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldFailToEncryptDocWithPasswordIfItsValidationHasFailed(@TempDir Path tempPath) {
        String passwordForEncrypt = "--password=passwordlabel:short";

        assertThrowsException(() ->
            checkCreateDecryptDoc(tempPath, passwordForEncrypt, passwordForEncrypt, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithTwoKeysAndDecryptWithPassword(@TempDir Path tempPath) throws IOException {
        createDocWithFewKeysButDecryptWithOneOfThem(
            tempPath,
            PASSWORD_OPTION,
            SECRET_OPTION,
            PASSWORD_OPTION,
            SUCCESSFUL_EXIT_CODE
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithTwoKeysAndDecryptWithSecret(@TempDir Path tempPath) throws IOException {
        createDocWithFewKeysButDecryptWithOneOfThem(
            tempPath,
            PASSWORD_OPTION,
            SECRET_OPTION,
            SECRET_OPTION,
            SUCCESSFUL_EXIT_CODE
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithOneKeyButTryToDecryptWithTwo(@TempDir Path tempPath) throws IOException {
        createDocWithOneKeyAndTryToDecryptWithFewKeys(
            tempPath,
            PASSWORD_OPTION,
            SECRET_OPTION,
            PASSWORD_OPTION,
            SUCCESSFUL_EXIT_CODE
        );
    }

    @Test
    void testSuccessfulReEncryption(@TempDir Path tempPath) throws IOException {

        String secret = "mysecret:base64," + Base64.getEncoder()
            .encodeToString("topSecret!".getBytes(StandardCharsets.UTF_8));
        String secretForEncrypt = "--secret=" + secret;
        String secretForDecrypt = "--secret=" + secret;

        String password = "passwordlabel:myPlainTextPassword";
        String passwordForEncrypt = "--encpassword=" + password;
        String passwordForDecrypt = "--password=" + password;

        reEncryptCDocAndTestToDecrypt(
            secretForEncrypt,
            secretForDecrypt,
            passwordForEncrypt,
            passwordForDecrypt,
            tempPath,
            SUCCESSFUL_EXIT_CODE
        );
    }

    @Test
    void shouldFailWithTheSameOutputDirectoryWhenReEncrypt(@TempDir Path tempPath) {

        String secret = "mysecret:base64," + Base64.getEncoder()
            .encodeToString("topSecret!".getBytes(StandardCharsets.UTF_8));

        String secretCmd = "--secret=" + secret;

        String password = "passwordlabel:myPlainTextPassword";
        String passwordForReEncrypt = "--encpassword=" + password;

        assertThrowsException(() ->
            failToReEncryptCDocWithTheSameOutputDir(
                secretCmd,
                secretCmd,
                passwordForReEncrypt,
                tempPath
            )
        );
    }

    private void checkCreateDecryptDocWithPublicKey(
        Path tempPath,
        String publicKey,
        String privateKey
    ) throws IOException {
        String publicKeyArg = "--pubkey=" + publicKey;
        String privateKeyArg = "--key=" + privateKey;

        checkCreateDecryptDoc(tempPath, publicKeyArg, privateKeyArg, SUCCESSFUL_EXIT_CODE);
    }

    private void checkCreateDecryptDoc(
        Path tempPath,
        String encryptionArgument,
        String decryptionArgument,
        int expectedDecryptExitCode
    ) throws IOException {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");
        int exitCode = cmd.execute("create",
                encryptionArgument,
                "--file=" + cdocFile,
                cdocCliPath.resolve("README.md").toString()
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, exitCode);

        var resultFile = cdocFile.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);

        Path outPath = tempPath.resolve("out");
        outPath.toFile().mkdir();

        out.reset();
        err.reset();

        int decryptExitCode = cmd.execute("decrypt",
                "--file=" + cdocFile,
                decryptionArgument,
                "--output=" + outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedDecryptExitCode, decryptExitCode);

        log.debug("Expected: {}", "Decrypting " + cdocFile.toFile() + " " + outPath);

        assertTrue(out.toString().startsWith("Decrypting " + cdocFile.toFile() + " to " + outPath));
        assertTrue(out.toString().contains("README.md"));

        String inReadme = Files.readString(cdocCliPath.resolve("README.md"));
        String outReadme = Files.readString(outPath.resolve("README.md"));

        assertEquals(inReadme, outReadme);
    }

    void createDocWithFewKeysButDecryptWithOneOfThem(
        Path tempPath,
        String encryptionArgument1,
        String encryptionArgument2,
        String decryptionArgument,
        int expectedDecryptExitCode
    ) throws IOException {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");
        int exitCode = cmd.execute("create",
            encryptionArgument1,
            encryptionArgument2,
            "--file=" + cdocFile,
            cdocCliPath.resolve("README.md").toString()
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, exitCode);

        var resultFile = cdocFile.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);

        Path outPath = tempPath.resolve("out");
        outPath.toFile().mkdir();

        out.reset();
        err.reset();

        int decryptExitCode = cmd.execute("decrypt",
            "--file=" + cdocFile,
            decryptionArgument,
            "--output=" + outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedDecryptExitCode, decryptExitCode);

        log.debug("Expected: {}", "Decrypting " + cdocFile.toFile() + " " + outPath);

        assertTrue(out.toString().startsWith("Decrypting " + cdocFile.toFile() + " to " + outPath));
        assertTrue(out.toString().contains("README.md"));

        String inReadme = Files.readString(cdocCliPath.resolve("README.md"));
        String outReadme = Files.readString(outPath.resolve("README.md"));

        assertEquals(inReadme, outReadme);
    }

    void createDocWithOneKeyAndTryToDecryptWithFewKeys(
        Path tempPath,
        String encryptionArgument,
        String decryptionArgument1,
        String decryptionArgument2,
        int expectedDecryptExitCode
    ) throws IOException {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");
        int exitCode = cmd.execute("create",
            encryptionArgument,
            "--file=" + cdocFile,
            cdocCliPath.resolve("README.md").toString()
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, exitCode);

        var resultFile = cdocFile.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);

        Path outPath = tempPath.resolve("out");
        outPath.toFile().mkdir();

        out.reset();
        err.reset();

        int decryptExitCode = cmd.execute("decrypt",
            "--file=" + cdocFile,
            decryptionArgument1,
            decryptionArgument2,
            "--output=" + outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedDecryptExitCode, decryptExitCode);

        log.debug("Expected: {}", "Decrypting " + cdocFile.toFile() + " " + outPath);

        assertTrue(out.toString().startsWith("Decrypting " + cdocFile.toFile() + " to " + outPath));
        assertTrue(out.toString().contains("README.md"));

        String inReadme = Files.readString(cdocCliPath.resolve("README.md"));
        String outReadme = Files.readString(outPath.resolve("README.md"));

        assertEquals(inReadme, outReadme);
    }

    void reEncryptCDocAndTestToDecrypt(
        String secretForEncrypt,
        String secretForDecryption,
        String passwordForEncryption,
        String passwordForDecryption,
        Path tempPath,
        int expectedExitCode
    ) throws IOException {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");

        // prepare encrypted CDOC container for further re-encryption
        cmd.execute("create",
            secretForEncrypt,
            "--file=" + cdocFile,
            cdocCliPath.resolve("README.md").toString()
        );

        // create output folder
        Path outPath = tempPath.resolve("out");
        if (outPath.toFile().mkdir()) {
            log.info("Created output folder {} for re-encryption", outPath);
        } else {
            throw new IOException("Failed to create output folder " + outPath.toFile());
        }

        // test re-encryption flow
        int exitCode = cmd.execute("re-encrypt",
            secretForDecryption,
            passwordForEncryption,
            "--file=" + cdocFile,
            "--output=" + outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedExitCode, exitCode);

        var resultFile = cdocFile.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);

        out.reset();
        err.reset();

        Path decryptionFilePath = outPath.resolve(resultFile.getName());
        // test to decrypt re-encrypted container
        int decryptExitCode = cmd.execute("decrypt",
            "--file=" + decryptionFilePath,
            passwordForDecryption,
            "--output=" + outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedExitCode, decryptExitCode);

        log.debug("Expected: {}", "Decrypting " + decryptionFilePath.toFile() + " " + outPath);

        assertTrue(out.toString().startsWith(
            "Decrypting " + decryptionFilePath.toFile() + " to " + outPath)
        );
        assertTrue(out.toString().contains("README.md"));

        String inReadme = Files.readString(cdocCliPath.resolve("README.md"));
        String outReadme = Files.readString(outPath.resolve("README.md"));

        assertEquals(inReadme, outReadme);
    }

    void failToReEncryptCDocWithTheSameOutputDir(
        String secretForEncrypt,
        String secretForDecryption,
        String passwordForEncryption,
        Path tempPath
    ) {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");

        // prepare encrypted CDOC container for further re-encryption
        cmd.execute("create",
            secretForEncrypt,
            "--file=" + cdocFile,
            cdocCliPath.resolve("README.md").toString()
        );

        // test re-encryption flow
        int exitCode = cmd.execute("re-encrypt",
            secretForDecryption,
            passwordForEncryption,
            "--file=" + cdocFile,
            "--output=" + tempPath.toFile()
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, exitCode);

        var resultFile = cdocFile.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);

        out.reset();
        err.reset();
    }

    private void assertThrowsException(Executable validation) {
        assertThrows(AssertionFailedError.class, validation);
    }

}
