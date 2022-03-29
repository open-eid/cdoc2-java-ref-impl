package ee.cyber.cdoc20.cli;

import ee.cyber.cdoc20.cli.commands.CDocCreateCmd;
import ee.cyber.cdoc20.cli.commands.CDocDecryptCmd;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@Command(
        version = {"cdoc20-cli version: 0.0.1", "cdoc20-lib version: 0.0.1"},
        name = "cdoc20-cli",
        header = "\r\ncdoc20-cli is a command line interface for cdoc20 library\r\n",
        customSynopsis = { "[create] <arguments>",
                "[decrypt] <arguments>" },
        subcommands = {CDocCreateCmd.class,
                CDocDecryptCmd.class}
)
public class CDocCli implements Callable<Void>{
    @Option(names = {"--version"}, versionHelp = true, description = "display version info")
    boolean versionInfoRequested;

    public static void main(String... args) {
        if (args.length == 0) {
            CommandLine.usage(new CDocCli(), System.out);
            CommandLine.usage(new CDocCreateCmd(), System.out);
            CommandLine.usage(new CDocDecryptCmd(), System.out);
        }
        int exitCode = new CommandLine(new CDocCli()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Void call() {
        return null;
    }
}
