package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.crypto.ECKeys;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.security.KeyPair;
import java.util.concurrent.Callable;

@Command(name = "decrypt", aliases = {"x", "extract"})
public class CDocDecryptCmd implements Callable<Void> {

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"}, required = true,
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    File privKeyFile;

    @Option(names = {"-o", "--output"},
            description = "output destination | Default: current-directory")
    private File outputPath = new File(".");

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Option(names = {"-ZZ"}, hidden = true, description = "inputFile will only be decrypted (result will be tar.gz)")
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
                .withDestinationDirectory(outputPath);

        cDocDecrypter.decrypt();
        return null;
    }
}
