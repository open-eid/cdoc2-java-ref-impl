package ee.cyber.cdoc20.cli;



import ee.cyber.cdoc20.cli.commands.CDocCreateCmd;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

@Command(
        version = {"cdoc20-cli version: 0.0.1", "cdoc20-lib version: 0.0.1"},
        name = "cdoc20-cli",
        header = "\r\ncdoc20-cli is a command line interface for cdoc20 library\r\n",
        customSynopsis = { "[create] <arguments>" },
        subcommands = {CDocCreateCmd.class}
)
public class CDocCli implements Callable<Void>{
    @Option(names = {"--version"}, versionHelp = true, description = "display version info")
    boolean versionInfoRequested;

    public static void main(String... args) {
        if (args.length == 0) {
            CommandLine.usage(new CDocCli(), System.out);
            CommandLine.usage(new CDocCreateCmd(), System.out);
        }
        CommandLine.call(new CDocCli(), System.err, args);
    }

    @Override
    public Void call() throws Exception {
        return null;
    }
}
