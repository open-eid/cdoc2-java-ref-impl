package ee.cyber.cdoc2.cli.commands;

import ee.cyber.cdoc2.FormattedOptionParts;
import ee.cyber.cdoc2.cli.SymmetricKeyUtil;
import ee.cyber.cdoc2.CDocBuilder;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;

import static ee.cyber.cdoc2.cli.CDocCommonHelper.getServerProperties;


//S106 - Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "create", aliases = {"c", "encrypt"}, showAtFileInUsageHelp = true)
public class CDocCreateCmd implements Callable<Void> {

    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    private static final String DURATION_FORMAT = "P(n)DT(n)H(n)M(n)S";

    // default server configuration disabled, until public key server is up and running
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost.properties";

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "CDOC", description = "the CDOC2 file")
    private File cdocFile;

    // one of cert or pubkey must be specified
    @CommandLine.ArgGroup(exclusive = false, multiplicity = "1..*")
    private Dependent recipient;

    static class Dependent {
        @Option(names = {"-p", "--pubkey"},
            paramLabel = "PEM", description = "recipient public key in PEM format")
        private File[] pubKeys;

        @Option(names = {"-c", "--cert"},
            paramLabel = "CER", description = "recipient x509 certificate in DER or PEM format")
        private File[] certs;

        @Option(names = {"-r", "--recipient", "--receiver"},
            paramLabel = "isikukood", description = "recipient id code (isikukood)")
        private String[] identificationCodes;

        @Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
            description = SymmetricKeyUtil.SECRET_DESCRIPTION)
        private String[] secrets;

        @Option(names = {"-pw", "--password"}, arity = "0..1",
            paramLabel = "<label>:<password>", description = SymmetricKeyUtil.PASSWORD_DESCRIPTION)
        private String password;
    }

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    private void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Option(names = {"-S", "--server"},
        paramLabel = "FILE.properties",
        description = "key server connection properties file"
        // default server configuration disabled, until public key server is up and running
        //, arity = "0..1"
        //, fallbackValue = DEFAULT_SERVER_PROPERTIES
    )
    private String keyServerPropertiesFile;

    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt", arity = "1..*")
    private File[] inputFiles;

    @Option(names = { "-exp", "--expiry" }, paramLabel = DURATION_FORMAT,
        description = "Key capsule expiry duration",
        converter = DurationConverter.class
    )
    private Duration keyCapsuleExpiryDuration;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("create --file {} --pubkey {} --cert {} --secret {} --password {} {}",
                cdocFile,
                Arrays.toString(recipient.pubKeys),
                Arrays.toString(recipient.certs),
                (recipient.secrets != null) ? "****" : null,
                (recipient.password != null) ? "****" : null,
                Arrays.toString(inputFiles));
        }




        CDocBuilder cDocBuilder = new CDocBuilder()
            .withPayloadFiles(Arrays.asList(inputFiles));

        if (keyServerPropertiesFile != null) {
            Properties p = getServerProperties(keyServerPropertiesFile);
            cDocBuilder.withServerProperties(p);
        }


        List<EncryptionKeyMaterial> symmetricKMs =
            SymmetricKeyUtil.getEncryptionKeyMaterialFromFormattedSecrets(recipient.secrets);

        List<EncryptionKeyMaterial> recipients = EncryptionKeyMaterial.collectionBuilder()
            .fromPublicKey(this.recipient.pubKeys)
            .fromX509Certificate(this.recipient.certs)
            // fetch authentication certificates' public keys for natural person identity codes
            .fromEId(this.recipient.identificationCodes)
            .build();

        if (recipient.password != null) {
            FormattedOptionParts passwordAndLabel
                = SymmetricKeyUtil.getPasswordAndLabel(recipient.password);

            recipients.addAll(
                EncryptionKeyMaterial.collectionBuilder().fromPassword(
                    passwordAndLabel.optionChars(), passwordAndLabel.label()).build());
        }

        recipients.addAll(symmetricKMs);

        cDocBuilder.withRecipients(recipients);

        if (keyCapsuleExpiryDuration != null) {
            setExpiryDurationOrLogWarn(cDocBuilder);
        }

        cDocBuilder.buildToFile(cdocFile);

        log.info("Created {}", cdocFile.getAbsolutePath());

        return null;
    }

    private void setExpiryDurationOrLogWarn(CDocBuilder cDocBuilder) {
        if (null != this.recipient.secrets || null != recipient.password) {
            String warnMsg = "Key capsule expiry duration cannot be requested for symmetric key "
                + "encryption";
            log.warn("WARNING: {}", warnMsg);
        } else {
            cDocBuilder.withCapsuleExpiryDuration(keyCapsuleExpiryDuration);
        }
    }

    public static class DurationConverter implements CommandLine.ITypeConverter<Duration> {
        @Override
        public Duration convert(String arg) {
            try {
                return Duration.parse(arg);
            } catch (DateTimeParseException e) {
                throw new CommandLine.TypeConversionException(
                    "Expiry duration format should be " + DURATION_FORMAT
                );
            }
        }
    }

}
