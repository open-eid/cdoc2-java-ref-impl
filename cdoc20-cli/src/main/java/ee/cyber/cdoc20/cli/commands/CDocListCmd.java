package ee.cyber.cdoc20.cli.commands;

import ee.cyber.cdoc20.CDocDecrypter;
import ee.cyber.cdoc20.crypto.ECKeys;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.security.KeyPair;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "list", aliases = {"l"})
public class CDocListCmd implements Callable<Void> {
    private final static Logger log = LoggerFactory.getLogger(CDocListCmd.class);
    @Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"}, required = true,
            paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    File privKeyFile;

    @Option(names = { "-v", "--verbose" }, description = "verbose")
    private boolean verbose = false;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;


    @Override
    public Void call() throws Exception {
        KeyPair keyPair = ECKeys.loadFromPem(privKeyFile);
        CDocDecrypter cDocDecrypter = new CDocDecrypter()
                .withCDoc(cdocFile)
                .withRecipient(keyPair)
                ;

        System.out.println("Listing contents of "+cdocFile);
        List<ArchiveEntry> files = cDocDecrypter.list();
        if (!verbose) {
            files.forEach(e -> System.out.println(e.getName()));
        } else {
            long maxFileSize = files.stream().mapToLong(ArchiveEntry::getSize).max().orElse(0);
            String format = " %" + Math.round(Math.log10(maxFileSize)) + "d %18s %s%n";
            files.forEach(e -> {
                String isoDateTime = LocalDateTime.ofInstant( e.getLastModifiedDate().toInstant(), ZoneId.systemDefault()).format(DateTimeFormatter.ISO_DATE_TIME);
                System.out.format(format, e.getSize(), isoDateTime , e.getName());
            });
        }

        return null;
    }
}
