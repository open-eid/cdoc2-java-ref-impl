package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.util.Resources;
import java.io.File;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "decrypt", aliases = {"x", "extract"})
public class CDocDecryptCmd implements Callable<Void> {
    // commented out until public key server is in live
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost_pkcs11.properties";

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    File privKeyFile;

    @Option(names = {"-p12"},
            paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
    String p12;

    @Option (names = {"-s", "--slot"},
            description = "Key from smart card slot used for decrypting. Default 0")
    Integer slot = 0;

    @Option(names = {"-o", "--output"}, paramLabel = "DIR",
            description = "output destination | Default: current-directory")
    private File outputPath = new File(".");

    @Option(names = {"--server"}, paramLabel = "FILE.properties"
            // commented out until public key server is in live
            //, arity = "0..1"
            //,defaultValue = DEFAULT_SERVER_PROPERTIES
    )
    private String keyServerPropertiesFile;

    @CommandLine.Parameters(description = "one or more files to decrypt", paramLabel = "fileToExtract")
    String[] filesToExtract = new String[0];

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }


    @Override
    public Void call() throws Exception {

        String openScLibPath = System.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY, null);
        Properties p;

        KeyCapsuleClientFactory keyCapsulesClientFactory = null;

        if (keyServerPropertiesFile != null) {
            p = new Properties();
            p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
            keyCapsulesClientFactory = KeyCapsuleClientImpl.createFactory(p);
        }

        KeyPair keyPair;
        if (p12 != null) {
            keyPair = PemTools.loadKeyPairFromP12File(p12);
        } else {
            keyPair = privKeyFile != null
                ? PemTools.loadKeyPair(privKeyFile)
                : ECKeys.loadFromPKCS11Interactively(openScLibPath, slot);
        }

        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withRecipient(keyPair)
                .withFilesToExtract(Arrays.asList(filesToExtract))
                .withKeyServers(keyCapsulesClientFactory)
                .withDestinationDirectory(outputPath);


        System.out.println("Decrypting " + cdocFile + " to " + outputPath.getAbsolutePath());
        List<String> extractedFileNames = cDocDecrypter.decrypt();
        extractedFileNames.forEach(System.out::println);
        return null;
    }
}
