package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.cli.util.InteractiveCommunicationUtil;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParamConverter;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParam;
import ee.cyber.cdoc2.cli.util.LabeledSecretConverter;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Map;

import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.cli.util.CliConstants;
import ee.cyber.cdoc2.CDocReEncrypter;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;

import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecryptionKeyMaterial;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getKeyCapsulesClientFactory;


//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@CommandLine.Command(name = "re-encrypt", aliases = {"re", "reencrypt"}, showAtFileInUsageHelp =
    true)
public class CDocReEncryptCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(CDocReEncryptCmd.class);

    @CommandLine.Option(names = {"-f", "--file" }, required = true,
        paramLabel = "CDOC", description = "the CDOC2 file")
    private File cdocFile;
    @CommandLine.ArgGroup(exclusive = true, multiplicity = "0..1")
    Exclusive exclusive;

    static class Exclusive {
        @CommandLine.Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "Private key PEM to use for decrypting")
        private File privKeyFile;

        @CommandLine.Option(names = {"-p12"},
            paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
        private String p12;

        @CommandLine.Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
            converter = LabeledSecretConverter.class,
            description = CliConstants.SECRET_DESCRIPTION
                + ". Used to decrypt existing CDOC container.")
        private LabeledSecret secret;

        @CommandLine.Option(names = {"-pw", "--password"}, arity = "0..1",
            converter = LabeledPasswordParamConverter.class,
            paramLabel = "<label>:<password>",
            description = CliConstants.PASSWORD_DESCRIPTION + ". Used to decrypt existing CDOC container.")
        private LabeledPasswordParam password;
    }

    @CommandLine.Option(names = {"-encpw", "--encpassword"}, arity = "0..1",
        converter = LabeledPasswordParamConverter.class,
        paramLabel = "<label>:<password>",
        description = CliConstants.PASSWORD_DESCRIPTION + ". Used for re-encryption part.")
    private LabeledPasswordParam reEncryptPasswordParam;

    @CommandLine.Option(names = {"-encs", "--encsecret"}, paramLabel = "<label>:<secret>",
        converter = LabeledSecretConverter.class,
        description = CliConstants.SECRET_DESCRIPTION + ". Used for re-encryption part.")
    private LabeledSecret reEncryptSecret;


    @CommandLine.Option(names = {"--slot"},
        description = "Smart card key slot to use for decrypting. Default: 0")
    private Integer slot = 0;

    @CommandLine.Option(names = {"-a", "--alias"},
        description = "Alias of the keystore entry to use for decrypting")
    private String keyAlias;

    @CommandLine.Option(names = {"-o", "--output"}, paramLabel = "DIR", required = true,
        description = "output destination")
    private File outputPath;

    @CommandLine.Option(names = {"--server"}, paramLabel = "FILE.properties"
        // commented out until public key server is in live
        //, arity = "0..1"
        //,defaultValue = DEFAULT_SERVER_PROPERTIES
    )
    private String keyServerPropertiesFile;

    @CommandLine.Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    // allow -Dkey for setting System properties
    @CommandLine.Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    private void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Override
    public Void call() throws Exception {
        if (!this.cdocFile.exists()) {
            throw new InvalidPathException(this.cdocFile.getAbsolutePath(), "Input CDOC file does not exist");
        }

        DecryptionKeyMaterial decryptionKeyMaterial = getDecryptionKeyMaterial(
            this.cdocFile,
            this.exclusive.password,
            this.exclusive.secret,
            this.exclusive.p12,
            this.exclusive.privKeyFile,
            this.slot,
            this.keyAlias
        );

        KeyCapsuleClientFactory keyCapsulesClientFactory = null;

        if (this.keyServerPropertiesFile != null) {
            keyCapsulesClientFactory = getKeyCapsulesClientFactory(this.keyServerPropertiesFile);
        }

        File destCdocFile = getDestinationFile();
        CDocReEncrypter cDocReEncrypter = new CDocReEncrypter(
            cdocFile,
            decryptionKeyMaterial,
            destCdocFile,
            extractSymmetricKeyEncKeyMaterial(),
            keyCapsulesClientFactory
        );
        cDocReEncrypter.reEncryptCDocContainer();

        log.info("Created {}", destCdocFile.getAbsolutePath());

        return null;
    }

    private EncryptionKeyMaterial extractSymmetricKeyEncKeyMaterial() {
        if (null != this.reEncryptPasswordParam) {
            LabeledPassword labeledPassword = (this.reEncryptPasswordParam.isEmpty())
                    ? InteractiveCommunicationUtil.readPasswordAndLabelInteractively(true)
                    : this.reEncryptPasswordParam.labeledPassword();

            return EncryptionKeyMaterial.fromPassword(
                labeledPassword.getPassword(), labeledPassword.getLabel()
            );
        }

        if (null != this.reEncryptSecret) {
            return EncryptionKeyMaterial.fromSecret(
                this.reEncryptSecret.getSecretKey(), this.reEncryptSecret.getLabel()
            );
        }

        throw new IllegalArgumentException("Cannot re-create document without password");
    }

    private File getDestinationFile() {
        Path outDir = this.outputPath.toPath().resolve(cdocFile.getName()).normalize();
        if (outDir.toString().equals(cdocFile.toPath().toString())) {
            throw new IllegalArgumentException("Output path has to differ from the "
                + "initial document location");
        }
        return outDir.toFile();
    }

}
