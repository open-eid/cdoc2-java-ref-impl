package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.cli.FormattedOptionParts;
import ee.cyber.cdoc20.cli.SymmetricKeyUtil;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.crypto.Pkcs11Tools;
import ee.cyber.cdoc20.util.Resources;
import java.io.File;
import java.nio.file.InvalidPathException;
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
@Command(name = "decrypt", aliases = {"x", "extract"}, showAtFileInUsageHelp = true)
public class CDocDecryptCmd implements Callable<Void> {
    // commented out until public key server is in live
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost_pkcs11.properties";

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "Private key PEM to use for decrypting")
    File privKeyFile;

    @Option(names = {"-p12"},
            paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
    String p12;

    @Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
            description = SymmetricKeyUtil.SECRET_DESCRIPTION)
    String secret;

    @Option(names = {"-pass", "--password"}, arity = "0..1",
        paramLabel = "<label>:<password>", description = SymmetricKeyUtil.PASSWORD_DESCRIPTION)
    String password;

    @Option (names = {"--slot"},
            description = "Smart card key slot to use for decrypting. Default: 0")
    Integer slot = 0;

    @Option(names = {"-a", "--alias"},
            description = "Alias of the keystore entry to use for decrypting")
    String keyAlias;

    @Option(names = {"-o", "--output"}, paramLabel = "DIR",
            description = "output destination | Default: current-directory")
    private final File outputPath = new File(".");

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
        if (!this.cdocFile.exists()) {
            throw new InvalidPathException(this.cdocFile.getAbsolutePath(), "Input CDOC file does not exist");
        }

        String pkcs11LibPath = System.getProperty(CDocConfiguration.PKCS11_LIBRARY_PROPERTY, null);
        Properties p;

        KeyCapsuleClientFactory keyCapsulesClientFactory = null;

        if (keyServerPropertiesFile != null) {
            p = new Properties();
            p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
            keyCapsulesClientFactory = KeyCapsuleClientImpl.createFactory(p);
        }

        DecryptionKeyMaterial decryptionKm = null;
        if (password != null) {
            FormattedOptionParts splitPassword
                = SymmetricKeyUtil.splitFormattedOption(this.password, EncryptionKeyOrigin.FROM_PASSWORD);
            decryptionKm = SymmetricKeyUtil.extractDecryptionKeyMaterialFromPassword(splitPassword);
        }
        if (secret != null) {
            decryptionKm = SymmetricKeyUtil.extractDecryptionKeyMaterial(secret);
        }

        if (decryptionKm == null)  {
            KeyPair keyPair;
            if (p12 != null) {
                keyPair = PemTools.loadKeyPairFromP12File(p12);
            } else {
                keyPair = privKeyFile != null
                        ? PemTools.loadKeyPair(privKeyFile)
                        : Pkcs11Tools.loadFromPKCS11Interactively(pkcs11LibPath, slot, keyAlias);
            }

            decryptionKm = DecryptionKeyMaterial.fromKeyPair(keyPair);
        }

        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withRecipient(decryptionKm)
                .withFilesToExtract(Arrays.asList(filesToExtract))
                .withKeyServers(keyCapsulesClientFactory)
                .withDestinationDirectory(outputPath);

        System.out.println("Decrypting " + cdocFile + " to " + outputPath.getAbsolutePath());
        List<String> extractedFileNames = cDocDecrypter.decrypt();
        extractedFileNames.forEach(System.out::println);
        return null;
    }
}
