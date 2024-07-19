import ee.cyber.cdoc2.cli.CDocCli;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Properties;

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

    private static Path cdocCliPath;
    private static Path cdocFile;
    private static Path outPath;

    final PrintStream originalOut = System.out;
    final PrintStream originalErr = System.err;
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    @BeforeEach // JUnit 5
    public void setUpStreams(@TempDir Path tempPath) {
        out.reset();
        err.reset();
        System.setOut(new PrintStream(out));
        System.setErr(new PrintStream(err));

        cdocFile = getCdocFilePath(tempPath);
        cdocCliPath = Path.of(".").toAbsolutePath().normalize();
        outPath = tempPath.resolve("out");
        outPath.toFile().mkdir();
    }

    @AfterEach // JUnit 5
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    void testCreateDecryptDocEC() throws IOException {
        successfullyDecryptDocWithPublicKey("keys/bob_pub.pem", "keys/bob.pem");
    }

    @Test
    void testCreateDecryptDocECShort() throws IOException {
        String publicKey = "keys/cdoc2client_pub.pem";
        String privateKey = "keys/cdoc2client.pem";

        successfullyDecryptDocWithPublicKey(publicKey, privateKey);
    }

    @Test
    void testCreateDecryptDocRSA() throws IOException {
        String publicKey = "keys/rsa_pub.pem";
        String privateKey = "keys/rsa_priv.pem";

        successfullyDecryptDocWithPublicKey(publicKey, privateKey);
    }

    @Test
    void testSuccessfulCreateDecryptDocWithPassword() throws IOException {
        encrypt(PASSWORD_OPTION);
        decrypt(PASSWORD_OPTION, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void testSuccessfulCreateDecryptDocWithSecret() throws IOException {
        encrypt(SECRET_OPTION);
        decrypt(SECRET_OPTION, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void failToEncryptDocWhenSecretInPlainText() {
        String secret = "--secret=secretLabel:secretCannotBeInPlainText";

        assertThrowsException(() ->
            encrypt(secret)
        );
    }

    @Test
    void shouldFailToEncryptDocWithSecretButDecryptWithPassword() {
        encrypt(SECRET_OPTION);

        assertThrowsException(() ->
            decrypt(PASSWORD_OPTION, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldFailToEncryptDocWithPasswordButDecryptWithSecret() {
        encrypt(PASSWORD_OPTION);

        assertThrowsException(() ->
            decrypt(SECRET_OPTION, FAILURE_EXIT_CODE)
        );
    }

    @Test
    void shouldFailToEncryptDocWithPasswordIfItsValidationHasFailed() {
        String passwordForEncrypt = "--password=passwordlabel:short";

        assertThrowsException(() ->
            encrypt(passwordForEncrypt)
        );
    }

    @Test
    void shouldSucceedToEncryptDocWithTwoKeysAndDecryptWithPassword() throws IOException {
        encryptWithTwoKeys(PASSWORD_OPTION, SECRET_OPTION);
        decrypt(PASSWORD_OPTION, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void shouldSucceedToEncryptDocWithTwoKeysAndDecryptWithSecret() throws IOException {
        encryptWithTwoKeys(PASSWORD_OPTION, SECRET_OPTION);
        decrypt(SECRET_OPTION, SUCCESSFUL_EXIT_CODE);
    }

    @Test
    void shouldSucceedToEncryptDocWithOneKeyButTryToDecryptWithTwo() throws IOException {
        encrypt(PASSWORD_OPTION);
        decryptWithTwoKeys(SECRET_OPTION, PASSWORD_OPTION, SUCCESSFUL_EXIT_CODE);
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


    @Test
    void infoShouldDisplayKeyLabelInDefaultFormatForPassword() throws IOException {
        encrypt(PASSWORD_OPTION);
        decrypt(PASSWORD_OPTION, SUCCESSFUL_EXIT_CODE);

        String expectedKeyLabel = "Password: V:1, LABEL:passwordlabel, TYPE:pw ";
        executeInfo(expectedKeyLabel, cdocFile);
    }

    @Test
    void infoShouldDisplayKeyLabelInPlainText() throws IOException {
        disableKeyLabelFormatting();

        encrypt(PASSWORD_OPTION);
        decrypt(PASSWORD_OPTION, SUCCESSFUL_EXIT_CODE);

        String expectedKeyLabel = "Password: LABEL:passwordlabel ";
        executeInfo(expectedKeyLabel, cdocFile);

        restoreDefaultKeyLabelFormat();
    }

    @Test
    void infoShouldDisplayKeyLabelInDefaultFormatForSecret() throws IOException {
        encrypt(SECRET_OPTION);
        decrypt(SECRET_OPTION, SUCCESSFUL_EXIT_CODE);

        String expectedKeyLabel
            = "SymmetricKey: V:1, LABEL:label_b64secret, TYPE:secret ";
        executeInfo(expectedKeyLabel, cdocFile);
    }

    @Test
    void infoShouldDisplayKeyLabelInPlainTextForSecret() throws IOException {
        disableKeyLabelFormatting();

        encrypt(SECRET_OPTION);
        decrypt(SECRET_OPTION, SUCCESSFUL_EXIT_CODE);

        String expectedKeyLabel = "SymmetricKey: LABEL:label_b64secret ";
        executeInfo(expectedKeyLabel, cdocFile);

        restoreDefaultKeyLabelFormat();
    }

    @Test
    void infoShouldDisplayKeyLabelInDefaultFormatForEc() throws IOException {
        successfullyDecryptDocWithPublicKey("keys/bob_pub.pem", "keys/bob.pem");

        String expectedKeyLabel = "EC PublicKey: V:1, FILE:bob_pub.pem, TYPE:pub_key ";
        executeInfo(expectedKeyLabel, cdocFile);
    }

    @Test
    void infoShouldDisplayKeyLabelInDefaultFormatForRsa() throws IOException {
        String publicKey = "keys/rsa_pub.pem";
        String privateKey = "keys/rsa_priv.pem";

        successfullyDecryptDocWithPublicKey(publicKey, privateKey);

        String expectedKeyLabel = "RSA PublicKey: V:1, FILE:rsa_pub.pem, TYPE:pub_key ";
        executeInfo(expectedKeyLabel, cdocFile);
    }

    private void successfullyDecryptDocWithPublicKey(
        String publicKey,
        String privateKey
    ) throws IOException {
        String publicKeyArg = "--pubkey=" + publicKey;
        String privateKeyArg = "--key=" + privateKey;

        encrypt(publicKeyArg);
        decrypt(privateKeyArg, SUCCESSFUL_EXIT_CODE);
    }

    private void reEncryptCDocAndTestToDecrypt(
        String secretForEncrypt,
        String secretForDecryption,
        String passwordForEncryption,
        String passwordForDecryption,
        Path tempPath,
        int expectedExitCode
    ) throws IOException {

        encrypt(secretForEncrypt);

        // create output folder
        Path outputPath = tempPath.resolve("out");
        if (outputPath.toFile().mkdir()) {
            log.info("Created output folder {} for re-encryption", outputPath);
        } else {
            throw new IOException("Failed to create output folder " + outputPath.toFile());
        }

        reEncrypt(outputPath, secretForDecryption, passwordForEncryption, expectedExitCode);

        Path decryptionFilePath = outputPath.resolve(cdocFile.toFile().getName());
        // test to decrypt re-encrypted container
        decrypt(
            decryptionFilePath,
            passwordForDecryption,
            outputPath,
            expectedExitCode
        );
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
        Path cdocPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdoc2File = tempPath.resolve("cdoc_cli_test.cdoc");

        // prepare encrypted CDOC container for further re-encryption
        cmd.execute("create",
            secretForEncrypt,
            "--file=" + cdoc2File,
            cdocPath.resolve("README.md").toString()
        );

        reEncrypt(cdoc2File, tempPath, secretForDecryption, passwordForEncryption, 0);
    }

    private void reEncrypt(
        Path outputPath,
        String secretForDecryption,
        String passwordForEncryption,
        int expectedExitCode
    ) {
        reEncrypt(cdocFile, outputPath, secretForDecryption, passwordForEncryption, expectedExitCode);
    }

    private void assertThrowsException(Executable validation) {
        assertThrows(AssertionFailedError.class, validation);
    }

    private Path getCdocFilePath(Path tempPath) {
        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        return tempPath.resolve("cdoc_cli_test.cdoc");
    }

    private void encrypt(String encryptionArgument) {
        String[] encryptArgs = createEncryptArgs(encryptionArgument, null);
        executeEncryption(encryptArgs, cdocFile);
    }

    private void encryptWithTwoKeys(String encryptionArgument1, String encryptionArgument2) {
        String[] encryptArgs = createEncryptArgs(encryptionArgument1, encryptionArgument2);
        executeEncryption(encryptArgs, cdocFile);
    }

    private void decrypt(String decryptionArgument, int expectedDecryptExitCode)
        throws IOException {

        String[] decryptArgs = createDecryptArgs(decryptionArgument, null);
        executeDecryptionWithDefaultPath(decryptArgs, expectedDecryptExitCode);
    }

    private void decrypt(
        Path decryptionFilePath,
        String decryptionArgument,
        Path outputPath,
        int expectedExitCode
    ) throws IOException {

        String[] decryptArgs = new String[]{
            "decrypt",
            "--file=" + decryptionFilePath,
            decryptionArgument,
            "--output=" + outputPath
        };
        executeDecryption(decryptArgs, decryptionFilePath, outputPath, cdocCliPath, expectedExitCode);
    }

    private void decryptWithTwoKeys(
        String decryptionArgument1,
        String decryptionArgument2,
        int expectedDecryptExitCode
    ) throws IOException {

        String[] decryptArgs = createDecryptArgs(decryptionArgument1, decryptionArgument2);
        executeDecryptionWithDefaultPath(decryptArgs, expectedDecryptExitCode);
    }

    private String[] createEncryptArgs(String encryptionArgument1, String encryptionArgument2) {
        if (null == encryptionArgument2) {
            return new String[]{
                "create",
                encryptionArgument1,
                "--file=" + cdocFile,
                cdocCliPath.resolve("README.md").toString()
            };
        }
        return new String[]{
            "create",
            encryptionArgument1,
            encryptionArgument2,
            "--file=" + cdocFile,
            cdocCliPath.resolve("README.md").toString()
        };
    }

    private String[] createDecryptArgs(String decryptionArgument1, String decryptionArgument2) {
        if (null == decryptionArgument2) {
            return new String[]{
                "decrypt",
                "--file=" + cdocFile,
                decryptionArgument1,
                "--output=" + outPath
            };
        }
        return new String[]{
            "decrypt",
            "--file=" + cdocFile,
            decryptionArgument1,
            decryptionArgument2,
            "--output=" + outPath
        };
    }

    private void executeEncryption(String[] encryptArgs, Path cdoc2File) {
        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        int exitCode = cmd.execute(encryptArgs);

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, exitCode);

        var resultFile = cdoc2File.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);
    }

    private void executeDecryptionWithDefaultPath(
        String[] decryptArgs,
        int expectedDecryptExitCode
    ) throws IOException {
        executeDecryption(decryptArgs, cdocFile, outPath, cdocCliPath, expectedDecryptExitCode);
    }

    private void executeDecryption(
        String[] decryptArgs,
        Path cdoc2File,
        Path outputPath,
        Path cdoc2Path,
        int expectedDecryptExitCode
    ) throws IOException {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        out.reset();
        err.reset();

        int decryptExitCode = cmd.execute(decryptArgs);

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedDecryptExitCode, decryptExitCode);

        log.debug("Expected: {}", "Decrypting " + cdoc2File.toFile() + " " + outputPath);

        assertTrue(out.toString().startsWith("Decrypting " + cdoc2File.toFile() + " to " + outputPath));
        assertTrue(out.toString().contains("README.md"));

        String inReadme = Files.readString(cdoc2Path.resolve("README.md"));
        String outReadme = Files.readString(outputPath.resolve("README.md"));

        assertEquals(inReadme, outReadme);
    }

    private void reEncrypt(
        Path cdoc2File,
        Path outputPath,
        String secretForDecryption,
        String passwordForEncryption,
        int expectedExitCode
    ) {
        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        // test re-encryption flow
        int exitCode = cmd.execute("re-encrypt",
            secretForDecryption,
            passwordForEncryption,
            "--file=" + cdoc2File,
            "--output=" + outputPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(expectedExitCode, exitCode);

        var resultFile = cdoc2File.toFile();
        assertTrue(resultFile.exists());
        assertTrue(resultFile.length() > 0);

        out.reset();
        err.reset();
    }

    private void executeInfo(String expectedKeyLabel, Path cdoc2File) {
        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        int exitCode = cmd.execute("info", "--file=" + cdoc2File);

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, exitCode);

        String executionOutput = out.toString();
        String outputWithoutBreaks = executionOutput.replace("\n", "");
        String[] split = outputWithoutBreaks.split("README.md");
        String actualOutputKeyLabel = split[split.length - 1];

        assertEquals(expectedKeyLabel, actualOutputKeyLabel);
    }

    private void disableKeyLabelFormatting() {
        Properties props = System.getProperties();
        props.setProperty(
            "ee.cyber.cdoc2.key-label.machine-readable-format.enabled",
            "false"
        );
    }

    private void restoreDefaultKeyLabelFormat() {
        Properties props = System.getProperties();
        props.setProperty(
            "ee.cyber.cdoc2.key-label.machine-readable-format.enabled",
            "true"
        );
    }

}
