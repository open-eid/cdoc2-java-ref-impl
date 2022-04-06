package ee.cyber.cdoc20.cli.commands;


import ee.cyber.cdoc20.CDocBuilder;
import ee.cyber.cdoc20.crypto.ECKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

//S106 - Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "create", aliases = {"c", "encrypt"})
public class CDocCreateCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"}, required = true,
            paramLabel = "PEM", description = "EC private key PEM used to encrypt")
    File privKeyFile;

    @Option(names = {"-p", "--pubkey", "--recipient", "--receiver"}, required = true,
            paramLabel = "PEM", description = "recipient public key")
    File[] pubKeyFiles;

    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt")
    File[] inputFiles;

    @Option(names = {"-ZZ"}, hidden = true,
            description = "inputFile will only be encrypted (inputFile is already tar.gz)")
    private boolean disableCompression = false;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("create --file {} --key {} --pubkey {} {}",
                    cdocFile, privKeyFile, Arrays.toString(pubKeyFiles), Arrays.toString(inputFiles));
        }
        KeyPair keyPair = ECKeys.loadFromPem(privKeyFile);
        List<ECPublicKey> recipients = ECKeys.loadECPubKeys(pubKeyFiles);

        if (disableCompression) {
            System.setProperty("ee.cyber.cdoc20.disableCompression", "true");
        }

        CDocBuilder cDocBuilder = new CDocBuilder()
                .withSender(keyPair)
                .withRecipients(recipients)
                .withPayloadFiles(Arrays.asList(inputFiles));

        cDocBuilder.buildToFile(cdocFile);

        log.info("Created {}", cdocFile);
        System.out.println("Created " + cdocFile.getAbsolutePath());

        return null;
    }
}
