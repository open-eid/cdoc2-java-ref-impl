package ee.cyber.cdoc20.cli.commands;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.util.Arrays;
import java.util.concurrent.Callable;

@Command(name = "create", aliases = {"c"})
public class CDocCreateCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    @Option(names = { "f", "-f", "--file" }, paramLabel = "FILE", description = "the CDOC2.0 file")
    File cdocFile;

    @Option(names = {"-k", "--key"}, paramLabel = "PEM", description = "EC private key PEM used to encrypt")
    File privKeyFile;

    @Option(names = {"-p", "--pubkey"}, paramLabel = "PEM", description = "recipient public key")
    File pubKeyFile;

    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt")
    File[] inputFiles;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {

        log.debug("--file {} {}", cdocFile, Arrays.toString(inputFiles));

        return null;
    }
}
