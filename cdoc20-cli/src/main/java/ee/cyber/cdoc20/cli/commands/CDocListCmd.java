package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.PemTools;
import org.apache.commons.compress.archivers.ArchiveEntry;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "list", aliases = {"l"})
public class CDocListCmd implements Callable<Void> {
    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"},
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    File privKeyFile;

    @Option (names = {"-s", "--slot"},
            description = "Key from smartcard slot used for decrypting. Default 0")
    Integer slot = 0;


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

        String openScLibPath = System.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY, null);
        KeyPair keyPair = (privKeyFile != null) ? PemTools.loadFromPem(privKeyFile)
                : ECKeys.loadFromPKCS11Interactively(openScLibPath, slot);

        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withRecipient(keyPair);

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
