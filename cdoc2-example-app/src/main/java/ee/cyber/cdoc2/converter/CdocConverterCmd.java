package ee.cyber.cdoc2.converter;

import ee.cyber.cdoc2.converter.util.CommonService;
import ee.cyber.cdoc2.converter.util.Util;
import org.openeid.cdoc4j.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.Callable;

@Command(name = "cdoc-convert")
@SuppressWarnings("squid:S106")
public class CdocConverterCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(CdocConverterCmd.class);

    @Option(names = {"-p12"}, required = true, paramLabel = "FILE.p12",
        description = "Load private key for decryption from .p12 file (FILE.p12:password)")
    String p12;

    @Option(names = {"-f", "-c", "--cdoc" }, required = true,
        paramLabel = "CDOC", description = "the CDOC file")
    File cdocFile;

    @Option(names = {"-o", "--out", "--cdoc2"}, required = false,
        paramLabel = "CDOC2", description = "the CDOC2 file")
    File cdoc2FileOption;

    @Option(names = { "--tmp"}, required = false,
        paramLabel = "DIR", description = "temp directory used for temporary files extracted from CDOC")
    Path tempDir = null;

    @Option(names= {"--label"}, required = false,
        paramLabel = "label", description = "cdoc2 recipient label")
    String labelOption;

    @Option(names = { "-h", "--help" }, usageHelp = false, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {

        char[] password = CommonService.askPassword();
        String label = CommonService.getLabel(labelOption);

        File cdoc2File = CommonService.getCdoc2File(cdoc2FileOption, cdocFile);

        Objects.requireNonNull(p12);
        Token token = Util.readPkcs12Token(p12);

        try (InputStream cdocIs = new FileInputStream(cdocFile)) {
            Util.reEncrypt(cdocIs, token, cdoc2File, label, password, tempDir);
        }

        System.out.println("Created cdoc2 " + cdoc2File.getAbsolutePath());

        return null;
    }
}
