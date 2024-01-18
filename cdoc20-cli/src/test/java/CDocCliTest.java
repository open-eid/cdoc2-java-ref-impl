import ee.cyber.cdoc20.cli.CDocCli;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opentest4j.AssertionFailedError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.*;

class CDocCliTest {
    private static final Logger log = LoggerFactory.getLogger(CDocCliTest.class);

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
        String publicKey = "keys/cdoc20client_pub.pem";
        String privateKey = "keys/cdoc20client.pem";

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
        String password = "passwordlabel:myPlainTextPassword";
        String passwordArg = "--password=" + password;
        checkCreateDecryptDoc(tempPath, passwordArg, passwordArg, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void testSuccessfulCreateDecryptDocWithSecret(@TempDir Path tempPath) throws IOException {
        String secret = "mylonglabel:longstringthatIcanremember,butothersdon'tknow";
        String secretArg = "--secret=" + secret;
        checkCreateDecryptDoc(tempPath, secretArg, secretArg, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void shouldFailToEncryptDocWithSecretButDecryptWithPassword(@TempDir Path tempPath) {
        String secret = "mylonglabel:longstringthatIcanremember,butothersdon'tknow";
        String secretForEncrypt = "--secret=" + secret;

        String password = "passwordlabel:myPlainTextPassword";
        String passwordForDecrypt = "--password=" + password;

        assertThrows(AssertionFailedError.class, () ->
            checkCreateDecryptDoc(tempPath, secretForEncrypt, passwordForDecrypt, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldFailToEncryptDocWithPasswordButDecryptWithSecret(@TempDir Path tempPath) {
        String password = "passwordlabel:myPlainTextPassword";
        String passwordForEncrypt = "--password=" + password;

        String secret = "mylonglabel:longstringthatIcanremember,butothersdon'tknow";
        String secretForDecrypt = "--secret=" + secret;

        assertThrows(AssertionFailedError.class, () ->
            checkCreateDecryptDoc(tempPath, passwordForEncrypt, secretForDecrypt, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithTwoKeysAndDecryptWithPassword(@TempDir Path tempPath) throws IOException {
        String password = "passwordlabel:myPlainTextPassword";
        String passwordForEncrypt = "--password=" + password;

        String secret = "mylonglabel:longstringthatIcanremember,butothersdon'tknow";
        String secretForEncrypt = "--secret=" + secret;

        String passwordForDecrypt = "--password=" + password;

        createDocWithFewKeysButDecryptWithOneOfThem(
            tempPath,
            passwordForEncrypt,
            secretForEncrypt,
            passwordForDecrypt,
            SUCCESSFUL_EXIT_CODE
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithTwoKeysAndDecryptWithSecret(@TempDir Path tempPath) throws IOException {
        String password = "passwordlabel:myPlainTextPassword";
        String passwordForEncrypt = "--password=" + password;

        String secret = "mylonglabel:longstringthatIcanremember,butothersdon'tknow";
        String secretForEncrypt = "--secret=" + secret;

        String secretForDecrypt = "--secret=" + secret;

        createDocWithFewKeysButDecryptWithOneOfThem(
            tempPath,
            passwordForEncrypt,
            secretForEncrypt,
            secretForDecrypt,
            SUCCESSFUL_EXIT_CODE
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithOneKeyButTryToDecryptWithTwo(@TempDir Path tempPath) throws IOException {
        String password = "passwordlabel:myPlainTextPassword";
        String passwordForEncrypt = "--password=" + password;

        String secret = "mylonglabel:longstringthatIcanremember,butothersdon'tknow";

        String secretForDecrypt = "--secret=" + secret;
        String passwordForDecrypt = "--password=" + password;

        createDocWithOneKeyAndTryToDecryptWithFewKeys(
            tempPath,
            passwordForEncrypt,
            secretForDecrypt,
            passwordForDecrypt,
            SUCCESSFUL_EXIT_CODE
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

}
