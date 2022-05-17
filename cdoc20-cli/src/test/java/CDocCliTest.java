import ee.cyber.cdoc20.cli.CDocCli;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    void testCreateDecryptDoc(@TempDir Path tempPath) {

        CDocCli app = new CDocCli();
        CommandLine cmd = new CommandLine(app);

        log.debug("Current dir {}", Path.of(".").toAbsolutePath());

        Path cdocCliPath = Path.of(".").toAbsolutePath().normalize();


        log.debug("Temp dir {}", tempPath.toAbsolutePath());
        Path cdocFile = tempPath.resolve("cdoc_cli_test.cdoc");
        int exitCode = cmd.execute("create",
                "--pubkey=keys/bob_pub.pem",
                "--file="+cdocFile,
                cdocCliPath.resolve("README.md").toString()
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);


        assertEquals(0, exitCode);

        assertNotNull(out);
        assertTrue(out.toString().startsWith("Created "+cdocFile));

        assertTrue(cdocFile.toFile().exists());


        Path outPath = tempPath.resolve("out");
        outPath.toFile().mkdir();


        out.reset();
        err.reset();

        int decryptExitCode = cmd.execute("decrypt",
                "--file="+cdocFile,
                "--key=keys/bob.pem",
                "--output="+outPath
        );

        log.debug("Output was: {}", out);
        log.debug("Err was: {}", err);

        assertEquals(0, decryptExitCode);

        log.debug("Expected: {}", "Decrypting "+cdocFile.toFile()+" "+outPath);

        assertTrue(out.toString().startsWith("Decrypting "+cdocFile.toFile()+" to "+outPath));
        assertTrue(out.toString().contains("README.md"));
    }
}
