package ee.cyber.cdoc2.converter;

import ee.cyber.cdoc2.converter.AsicConverterCmd;
import ee.cyber.cdoc2.converter.CdocConverterCmd;
import ee.cyber.cdoc2.converter.CreateAsicContainerCmd;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@SuppressWarnings("java:S106")
@Command(
        version = {"cdoc2-cli version: 1.6.0", "cdoc2-lib version: 3.0.0"},
        name = "cdoc2-example-app",
        header = "\r\ncdoc2-example-app is a command line interface for converting cdoc or asic "
            + "documents to cdoc2\r\n",
        customSynopsis = { "cdoc [cdoc-convert] <arguments>",
                "cdoc [asic] <arguments>", "cdoc [asic-convert] <arguments>"},
        subcommands = {CdocConverterCmd.class, CreateAsicContainerCmd.class, AsicConverterCmd.class}
)
public class CDocConverterCli implements Callable<Void> {

    public static void main(String... args) {
        if (args.length == 0) {
            CommandLine.usage(new CDocConverterCli(), System.out);
            CommandLine.usage(new CdocConverterCmd(), System.out);
            CommandLine.usage(new CreateAsicContainerCmd(), System.out);
            CommandLine.usage(new AsicConverterCmd(), System.out);
        }
        int exitCode = new CommandLine(new CDocConverterCli()).execute(args);

        System.exit(exitCode);
    }

    @Override
    public Void call() {
        return null;
    }
}
