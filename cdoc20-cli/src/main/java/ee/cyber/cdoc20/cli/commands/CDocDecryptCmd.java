package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.crypto.ECKeys;
import picocli.CommandLine;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "decrypt", aliases = {"x", "extract"})
public class CDocDecryptCmd implements Callable<Void> {

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"}, required = true,
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    File privKeyFile;

    @Option(names = {"-o", "--output"}, paramLabel = "DIR",
            description = "output destination | Default: current-directory")
    private File outputPath = new File(".");

    @CommandLine.Parameters(description = "one or more files to decrypt")
    String[] filesToExtract = new String[0];

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Option(names = {"-ZZ"}, hidden = true, description = "decrypt CDOC content as tar.gz file (no uncompress)")
    private boolean disableCompression = false;


    @Override
    public Void call() throws Exception {
        if (disableCompression) {
            System.setProperty("ee.cyber.cdoc20.disableCompression", "true");
            System.setProperty("ee.cyber.cdoc20.cDocFile", cdocFile.getName());
        }

        KeyPair keyPair = ECKeys.loadFromPem(privKeyFile);
        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withRecipient(keyPair)
                .withFilesToExtract(Arrays.asList(filesToExtract))
                .withDestinationDirectory(outputPath);

        System.out.println("Decrypting " + cdocFile + " to " + outputPath.getAbsolutePath());
        List<String> extractedFileNames = cDocDecrypter.decrypt();
        extractedFileNames.forEach(f -> System.out.println(f));
        return null;
    }
}
