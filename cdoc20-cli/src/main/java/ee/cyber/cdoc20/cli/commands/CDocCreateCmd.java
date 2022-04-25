package ee.cyber.cdoc20.cli.commands;


import ee.cyber.cdoc20.EccPubKeyCDocBuilder;
import ee.cyber.cdoc20.crypto.ECKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

//S106 - Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "create", aliases = {"c", "encrypt"})
public class CDocCreateCmd implements Callable<Void> {


    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"}, required = false,
            paramLabel = "PEM", description = "EC private key PEM used to encrypt")
    File privKeyFile;


    // one of cert or pubkey must be specified
    @CommandLine.ArgGroup(exclusive = false, multiplicity = "1..*")
    Dependent recipientFiles;
    static class Dependent {
        @Option(names = {"-p", "--pubkey", "--recipient", "--receiver",}, required = false,
                paramLabel = "PEM", description = "recipient public key as key pem")
        File[] pubKey;

        @Option(names = {"-c", "--cert"}, required = false,
                paramLabel = "DER", description = "recipient as x509 certificate in der format")
        File[] cert;
    }

    // Only secp384r1 supported, no point to expose this option to user
    @Option (names = {"--curve"}, hidden = true, defaultValue="secp384r1", description = "Elliptic curve used, default secp384r1")
    String curveName = ECKeys.SECP_384_R_1;

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt")
    File[] inputFiles;

    // For testing only
    @Option(names = {"-ZZ"}, hidden = true,
            description = "inputFile will only be encrypted (inputFile is already tar.gz)")
    private boolean disableCompression = false;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {



        if (log.isDebugEnabled()) {
            log.debug("create --file {} --key {} --pubkey {} --cert {} {}",
                    cdocFile,
                    privKeyFile,
                    Arrays.toString(recipientFiles.pubKey),
                    Arrays.toString(recipientFiles.cert),
                    Arrays.toString(inputFiles));
        }

        if (disableCompression) {
            System.setProperty("ee.cyber.cdoc20.disableCompression", "true");
        }

        List<ECPublicKey> recipients = ECKeys.loadECPubKeys(recipientFiles.pubKey);
        recipients.addAll(ECKeys.loadCertKeys(recipientFiles.cert));


        EccPubKeyCDocBuilder cDocBuilder = new EccPubKeyCDocBuilder()
                .withCurve(curveName)
                .withRecipients(recipients)
                .withPayloadFiles(Arrays.asList(inputFiles));

        if (privKeyFile != null) {
             cDocBuilder.withSender(ECKeys.loadFromPem(privKeyFile));
        } else {
             cDocBuilder.withGeneratedSender();
        }

        cDocBuilder.buildToFile(cdocFile);

        log.info("Created {}", cdocFile);
        System.out.println("Created " + cdocFile.getAbsolutePath());

        return null;
    }
}
