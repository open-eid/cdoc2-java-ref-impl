package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.cli.SymmetricKeyUtil;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.crypto.Pkcs11Tools;
import ee.cyber.cdoc20.util.Resources;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.security.KeyPair;
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

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "list", aliases = {"l"}, showAtFileInUsageHelp = true)
public class CDocListCmd implements Callable<Void> {
    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
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
            description = "Key from smartcard slot used for decrypting. Default 0")
    Integer slot = 0;

    @Option(names = {"-a", "--alias"},
            description = "Alias of the keystore entry to use for decrypting")
    String keyAlias;

    @Option(names = {"--server"}, paramLabel = "FILE.properties")
    private String keyServerPropertiesFile;

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    void setProperty(Map<String, String> props) {
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

        String pkcs11LibPath = System.getProperty(CDocConfiguration.PKCS11_LIBRARY_PROPERTY, null);
        Properties p;

        KeyCapsuleClientFactory keyCapsulesClient = null;

        if (keyServerPropertiesFile != null) {
            p = new Properties();
            p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
            keyCapsulesClient = KeyCapsuleClientImpl.createFactory(p);
        }

        DecryptionKeyMaterial decryptionKm = null;
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
                .withKeyServers(keyCapsulesClient)
                .withRecipient(decryptionKm);

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
