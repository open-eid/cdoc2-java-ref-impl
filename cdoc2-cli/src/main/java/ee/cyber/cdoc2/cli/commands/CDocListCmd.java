package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.cli.util.LabeledPasswordParam;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParamConverter;
import ee.cyber.cdoc2.cli.util.LabeledSecretConverter;
import ee.cyber.cdoc2.cli.util.CliConstants;
import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;
import ee.cyber.cdoc2.util.Resources;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;
import org.apache.commons.compress.archivers.ArchiveEntry;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecryptionKeyMaterial;

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "list", aliases = {"l"}, showAtFileInUsageHelp = true)
public class CDocListCmd implements Callable<Void> {
    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2 file")
    private File cdocFile;

    @Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    private File privKeyFile;

    @Option(names = {"-p12"},
            paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
    private String p12;

    @Option(names = {"-s", "--secret"},
        paramLabel = "<label>:<secret>",
        converter = LabeledSecretConverter.class,
        description = CliConstants.SECRET_DESCRIPTION)
    private LabeledSecret secret;

    @Option(names = {"-pass", "--password"}, arity = "0..1",
        paramLabel = "<label>:<password>",
        converter = LabeledPasswordParamConverter.class,
        description = CliConstants.PASSWORD_DESCRIPTION)
    private LabeledPasswordParam labeledPasswordParam;

    @Option (names = {"--slot"},
            description = "Key from smartcard slot used for decrypting. Default 0")
    private Integer slot = 0;

    @Option(names = {"-a", "--alias"},
            description = "Alias of the keystore entry to use for decrypting")
    private String keyAlias;

    @Option(names = {"--server"}, paramLabel = "FILE.properties")
    private String keyServerPropertiesFile;

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    private void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Option(names = { "-v", "--verbose" }, description = "verbose")
    private boolean verbose = false;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {
        if (!this.cdocFile.exists()) {
            throw new InvalidPathException(this.cdocFile.getAbsolutePath(), "Input CDOC file does not exist");
        }

        Properties p;

        KeyCapsuleClientFactory keyCapsulesClient = null;

        if (keyServerPropertiesFile != null) {
            p = new Properties();
            p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
            keyCapsulesClient = KeyCapsuleClientImpl.createFactory(p);
        }

        DecryptionKeyMaterial decryptionKeyMaterial = getDecryptionKeyMaterial(
            this.cdocFile,
            this.labeledPasswordParam,
            this.secret,
            this.p12,
            this.privKeyFile,
            this.slot,
            this.keyAlias
        );

        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withKeyServers(keyCapsulesClient)
                .withRecipient(decryptionKeyMaterial);

        System.out.println("Listing contents of " + cdocFile);
        List<ArchiveEntry> files = cDocDecrypter.list();
        if (!verbose) {
            files.forEach(e -> System.out.println(e.getName()));
        } else {
            long maxFileSize = files.stream().mapToLong(ArchiveEntry::getSize).max().orElse(0);
            String format = " %" + Math.round(Math.log10(maxFileSize)) + "d %18s %s%n";
            files.forEach(e -> {
                String isoDateTime = LocalDateTime.ofInstant(e.getLastModifiedDate().toInstant(),
                        ZoneId.systemDefault()).format(DateTimeFormatter.ISO_DATE_TIME);
                System.out.format(format, e.getSize(), isoDateTime, e.getName());
            });
        }

        return null;
    }
}
