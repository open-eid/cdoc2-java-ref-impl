package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.cli.util.LabeledPasswordParamConverter;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParam;
import ee.cyber.cdoc2.cli.util.LabeledSecretConverter;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.util.List;
import java.util.Map;

import java.util.concurrent.Callable;

import ee.cyber.cdoc2.cli.util.CliConstants;
import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;

import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecrypterWithFilesExtraction;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecryptionKeyMaterial;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getKeyCapsulesClientFactory;

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings({"java:S106", "java:S125"})
@Command(name = "decrypt", aliases = {"x", "extract"}, showAtFileInUsageHelp = true)
public class CDocDecryptCmd implements Callable<Void> {
    // commented out until public key server is in live
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost_pkcs11.properties";

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2 file")
    private File cdocFile;

    @CommandLine.ArgGroup(exclusive = true, multiplicity = "0..1")
    Exclusive exclusive;

    static class Exclusive {
        @Option(names = {"-k", "--key"},
                paramLabel = "PEM", description = "Private key PEM to use for decrypting")
        private File privKeyFile;

        @Option(names = {"-p12"},
                paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
        private String p12;

        @Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
                converter = LabeledSecretConverter.class,
                description = CliConstants.SECRET_DESCRIPTION)
        private LabeledSecret secret;

        @Option(names = {"-pw", "--password"}, arity = "0..1",
            converter = LabeledPasswordParamConverter.class,
            paramLabel = "<label>:<password>", description = CliConstants.PASSWORD_DESCRIPTION)
        // if empty --pw was provided labeledPasswordParam.isEmpty() is true
        // if option was not provided then labeledPasswordParam is null
        private LabeledPasswordParam labeledPasswordParam;
    }

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
            this.exclusive.labeledPasswordParam,
            this.exclusive.secret,
            this.exclusive.p12,
            this.exclusive.privKeyFile,
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
