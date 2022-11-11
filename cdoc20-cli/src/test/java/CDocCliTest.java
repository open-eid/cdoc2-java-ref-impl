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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CDocCliTest {
    private static final Logger log = LoggerFactory.getLogger(CDocCliTest.class);

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
        checkCreateDecryptDoc("keys/bob_pub.pem", "keys/bob.pem", tempPath);
    }

    @Test
    void testCreateDecyptDocECShort(@TempDir Path tempPath) throws IOException {
        checkCreateDecryptDoc("keys/cdoc20client_pub.pem", "keys/cdoc20client.pem", tempPath);
    }

    @Test
    void testCreateDecryptDocRSA(@TempDir Path tempPath) throws IOException {
        checkCreateDecryptDoc("keys/rsa_pub.pem", "keys/rsa_priv.pem", tempPath);
    }

    void checkCreateDecryptDoc(String pubKeyFile, String privateKeyFile, Path tempPath) throws IOException {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();

        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");
        int exitCode = cmd.execute("create",
                "--pubkey=" + pubKeyFile,
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
                "--key=" + privateKeyFile,
                "--output=" + outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, decryptExitCode);

        log.debug("Expected: {}", "Decrypting " + cdocFile.toFile() + " " + outPath);

        assertTrue(out.toString().startsWith("Decrypting " + cdocFile.toFile() + " to " + outPath));
        assertTrue(out.toString().contains("README.md"));

        String inReadme = Files.readString(cdocCliPath.resolve("README.md"));
        String outReadme = Files.readString(outPath.resolve("README.md"));

        assertEquals(inReadme, outReadme);
    }
}
