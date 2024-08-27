package ee.cyber.cdoc2.converter;

import ee.cyber.cdoc2.converter.util.PasswordCheckUtil;
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
import java.util.Arrays;
import java.util.concurrent.Callable;

@Command( name = "cdoc-convert")
@SuppressWarnings("squid:S106")
public class ConverterCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(ConverterCmd.class);

    @Option(names = {"-p12"}, required = true,
        paramLabel = "FILE.p12",
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

    public static void main(String... args) {

        if (args.length == 0) {
            CommandLine.usage(new ConverterCmd(), System.out);
            System.exit(1);
        }

        int exitCode = new CommandLine(new ConverterCmd()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Void call() throws Exception {

        Token token = Util.readPkcs12Token(p12);
        File cdoc2File = (cdoc2FileOption != null) ? cdoc2FileOption: Util.genCDoc2Filename(cdocFile);

        char[] password = Util.readPasswordInteractively(Util.PROMPT);
        char[] password2 = Util.readPasswordInteractively(Util.PROMPT_RENTER);

        if (!Arrays.equals(password, password2)) {
            System.out.println(Util.PW_DONT_MATCH);
            throw new IllegalArgumentException(Util.PW_DONT_MATCH);
        }

        if (!PasswordCheckUtil.isValidLength(password)) {
            System.out.println(PasswordCheckUtil.PW_LEN_ERR_STR);
            throw new IllegalArgumentException(PasswordCheckUtil.PW_LEN_ERR_STR);
        }

        if (PasswordCheckUtil.isPwned(password)) {
            System.out.println(PasswordCheckUtil.PASSWORD_IS_ALREADY_COMPROMISED);
            throw new IllegalArgumentException(PasswordCheckUtil.PASSWORD_IS_ALREADY_COMPROMISED);
        }

        String label = (labelOption != null) ? labelOption : Util.genPwLabel();
        if (labelOption == null) {
            System.out.println("Generated CDOC2 label: " + label);
        }

        try (InputStream cdocIs = new FileInputStream(cdocFile)) {

            Util.reEncrypt(cdocIs, token, cdoc2File, label, password, tempDir);

            System.out.println("Created cdoc2 " + cdoc2File.getAbsolutePath());
        }

        return null;
    }

}