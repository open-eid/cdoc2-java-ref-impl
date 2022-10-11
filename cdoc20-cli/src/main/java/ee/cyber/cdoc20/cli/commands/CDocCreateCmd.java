package ee.cyber.cdoc20.cli.commands;


import ee.cyber.cdoc20.EccPubKeyCDocBuilder;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.util.LdapUtil;
import ee.cyber.cdoc20.util.Resources;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;

//S106 - Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "create", aliases = {"c", "encrypt"})
public class CDocCreateCmd implements Callable<Void> {


    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    // default server configuration disabled, until public key server is up and running
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost.properties";

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    // one of cert or pubkey must be specified
    @CommandLine.ArgGroup(exclusive = false, multiplicity = "1..*")
    Dependent recipient;
    static class Dependent {
        @Option(names = {"-p", "--pubkey"},
                paramLabel = "PEM", description = "recipient public key as key pem")
        File[] pubKeys;

        @Option(names = {"-c", "--cert"},
                paramLabel = "CER", description = "recipient x509 certificate in DER or PEM format")
        File[] certs;

        @Option(names = {"-r", "--recipient", "--receiver"},
                paramLabel = "isikukood", description = "recipient id code (isikukood)")
        String[] identificationCodes;
    }

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Option(names = {"-S", "--server"},
            paramLabel = "FILE.properties",
            description = "Key server connection properties file"
            // default server configuration disabled, until public key server is up and running
            //, arity = "0..1"
            //, fallbackValue = DEFAULT_SERVER_PROPERTIES
    )
    String keyServerPropertiesFile;


    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt", arity = "1..*")
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
            log.debug("create --file {} --pubkey {} --cert {} {}",
                    cdocFile,
                    Arrays.toString(recipient.pubKeys),
                    Arrays.toString(recipient.certs),
                    Arrays.toString(inputFiles));
        }

        if (disableCompression) {
            System.setProperty("ee.cyber.cdoc20.disableCompression", "true");
        }

        List<ECPublicKey> recipients = new LinkedList<>();
        recipients.addAll(ECKeys.loadECPubKeys(this.recipient.pubKeys));
        recipients.addAll(ECKeys.loadCertKeys(this.recipient.certs));

        List<ECPublicKey> ldapKeys = LdapUtil.getCertKeys(this.recipient.identificationCodes).stream()
                .filter(ECKeys.EllipticCurve::isSupported)
                .map(publicKey -> (ECPublicKey)publicKey)
                .toList();

        recipients.addAll(ldapKeys);


        EccPubKeyCDocBuilder cDocBuilder = new EccPubKeyCDocBuilder()
                .withRecipients(recipients)
                .withPayloadFiles(Arrays.asList(inputFiles));

        if (keyServerPropertiesFile != null) {
            Properties p = new Properties();
            p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
            cDocBuilder.withServerProperties(p);
        }

        cDocBuilder.buildToFile(cdocFile);

        log.info("Created {}", cdocFile);
        System.out.println("Created " + cdocFile.getAbsolutePath());

        return null;
    }
}
