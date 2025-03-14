package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.cli.DecryptionKeyExclusiveArgument;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.services.Cdoc2Services;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.util.List;
import java.util.Map;

import java.util.concurrent.Callable;

import ee.cyber.cdoc2.CDocDecrypter;

import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecrypterWithFilesExtraction;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecryptionKeyMaterial;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getSmartCardDecryptionKeyMaterial;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_CAPSULE_PROPERTIES;


//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings({"java:S106", "java:S125"})
@Command(name = "decrypt", aliases = {"x", "extract"}, showAtFileInUsageHelp = true)
public class CDocDecryptCmd implements Callable<Void> {
    // commented out until public key server is in live
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost_pkcs11.properties";

    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC2", description = "the CDOC2 file")
    private File cdocFile;

    @CommandLine.ArgGroup
    DecryptionKeyExclusiveArgument exclusive;

    @Option (names = {"--slot"},
            description = "Smart card key slot to use for decrypting. Default: 0")
    private Integer slot = 0;

    @Option(names = {"-a", "--alias"},
            description = "Alias of the keystore entry to use for decrypting")
    private String keyAlias;

    @Option(names = {"-o", "--output"}, paramLabel = "DIR",
            description = "output destination | Default: current-directory")
    private File outputPath = new File(".");

    private String keyServerPropertiesFile;
    @Option(names = {"--server"}, paramLabel = "FILE.properties")
    private void setKeyServerPropertiesFile(String server) {
        keyServerPropertiesFile = server;
        System.setProperty(KEY_CAPSULE_PROPERTIES, keyServerPropertiesFile);
    }

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

        DecryptionKeyMaterial decryptionKeyMaterial = (null == this.exclusive)
            ? getSmartCardDecryptionKeyMaterial(this.slot, this.keyAlias)
            : getDecryptionKeyMaterial(this.cdocFile, this.exclusive);

        CDocDecrypter cDocDecrypter = getDecrypterWithFilesExtraction(
            this.cdocFile,
            this.filesToExtract,
            this.outputPath,
            decryptionKeyMaterial,
            Cdoc2Services.initFromSystemProperties()
        );

        System.out.println("Decrypting " + this.cdocFile + " to " + this.outputPath.getAbsolutePath());
        List<String> extractedFileNames = cDocDecrypter.decrypt();
        extractedFileNames.forEach(System.out::println);
        return null;
    }

}
