package ee.cyber.cdoc20.cli.commands;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.cli.SymmetricKeyUtil;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;

import static ee.cyber.cdoc20.cli.CDocDecryptionHelper.getDecrypterWithFilesExtraction;
import static ee.cyber.cdoc20.cli.CDocDecryptionHelper.getDecryptionKeyMaterial;
import static ee.cyber.cdoc20.cli.CDocDecryptionHelper.getKeyCapsulesClientFactory;

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "decrypt", aliases = {"x", "extract"}, showAtFileInUsageHelp = true)
public class CDocDecryptCmd implements Callable<Void> {
    // commented out until public key server is in live
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost_pkcs11.properties";

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    private File cdocFile;

    @Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "Private key PEM to use for decrypting")
    private File privKeyFile;

    @Option(names = {"-p12"},
            paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
    private String p12;

    @Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
            description = SymmetricKeyUtil.SECRET_DESCRIPTION)
    private String secret;

    @Option(names = {"-pw", "--password"}, arity = "0..1",
        paramLabel = "<label>:<password>", description = SymmetricKeyUtil.PASSWORD_DESCRIPTION)
    private String password;

    @Option (names = {"--slot"},
            description = "Smart card key slot to use for decrypting. Default: 0")
    private Integer slot = 0;

    @Option(names = {"-a", "--alias"},
            description = "Alias of the keystore entry to use for decrypting")
    private String keyAlias;

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
    private String[] filesToExtract = new String[0];

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    private void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Override
    public Void call() throws Exception {
        if (!this.cdocFile.exists()) {
            throw new InvalidPathException(this.cdocFile.getAbsolutePath(), "Input CDOC file does not exist");
        }

        KeyCapsuleClientFactory keyCapsulesClientFactory = null;
        if (this.keyServerPropertiesFile != null) {
            keyCapsulesClientFactory = getKeyCapsulesClientFactory(this.keyServerPropertiesFile);
        }

        DecryptionKeyMaterial decryptionKeyMaterial = getDecryptionKeyMaterial(
            this.cdocFile,
            this.password,
            this.secret,
            this.p12,
            this.privKeyFile,
            this.slot,
            this.keyAlias
        );

        CDocDecrypter cDocDecrypter = getDecrypterWithFilesExtraction(
            this.cdocFile,
            this.filesToExtract,
            this.outputPath,
            decryptionKeyMaterial,
            keyCapsulesClientFactory
        );

        System.out.println("Decrypting " + this.cdocFile + " to " + this.outputPath.getAbsolutePath());
        List<String> extractedFileNames = cDocDecrypter.decrypt();
        extractedFileNames.forEach(System.out::println);
        return null;
    }

}
