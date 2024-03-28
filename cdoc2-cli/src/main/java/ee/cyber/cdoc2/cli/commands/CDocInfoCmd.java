package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.container.recipients.PublicKeyRecipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.container.recipients.ServerRecipient;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

//S106 Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@CommandLine.Command(name = "info",  showAtFileInUsageHelp = true)
public class CDocInfoCmd implements Callable<Void> {
    @CommandLine.Option(names = {"-f", "--file" }, required = true,
            paramLabel = "CDOC", description = "the CDOC2 file")
    private File cdocFile;

    // allow -Dkey for setting System properties
    @CommandLine.Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    private void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @CommandLine.Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {


        List<Recipient> recipients = Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()));
        for (Recipient recipient: recipients) {

            String type = (recipient instanceof PublicKeyRecipient)
                    ? ((PublicKeyRecipient) recipient).getRecipientPubKey().getAlgorithm() + " PublicKey"
                    : "SymmetricKey";

            String label = recipient.getRecipientKeyLabel();

            String server = (recipient instanceof ServerRecipient)
                    ? "(server: " + ((ServerRecipient) recipient).getKeyServerId() + ")"
                    : "";

            System.out.println(type + ": " + label + " " + server);
        }

        return null;
    }
}
