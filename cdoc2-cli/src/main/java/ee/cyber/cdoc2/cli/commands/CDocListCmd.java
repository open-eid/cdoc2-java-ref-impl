package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.cli.DecryptionKeyExclusiveArgument;
import ee.cyber.cdoc2.CDocDecrypter;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import org.apache.commons.compress.archivers.ArchiveEntry;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getDecryptionKeyMaterial;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getKeyCapsulesClientFactory;
import static ee.cyber.cdoc2.cli.util.CDocDecryptionHelper.getSmartCardDecryptionKeyMaterial;


//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "list", aliases = {"l"}, showAtFileInUsageHelp = true)
public class CDocListCmd implements Callable<Void> {
    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2 file")
    private File cdocFile;

    @CommandLine.ArgGroup
    DecryptionKeyExclusiveArgument exclusive;

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

        KeyCapsuleClientFactory keyCapsulesClientFactory = null;
        if (keyServerPropertiesFile != null) {
            keyCapsulesClientFactory = getKeyCapsulesClientFactory(this.keyServerPropertiesFile);
        }

        DecryptionKeyMaterial decryptionKeyMaterial = (null == this.exclusive)
            ? getSmartCardDecryptionKeyMaterial(this.slot, this.keyAlias)
            : getDecryptionKeyMaterial(
                this.cdocFile,
                this.exclusive.getLabeledPasswordParam(),
                this.exclusive.getSecret(),
                this.exclusive.getP12(),
                this.exclusive.getPrivKeyFile()
                );

        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withKeyServers(keyCapsulesClientFactory)
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
