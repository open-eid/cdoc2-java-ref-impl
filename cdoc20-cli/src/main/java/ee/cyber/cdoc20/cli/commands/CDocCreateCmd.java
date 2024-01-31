package ee.cyber.cdoc20.cli.commands;


import ee.cyber.cdoc20.CDocBuilder;
import ee.cyber.cdoc20.CDocValidationException;
import ee.cyber.cdoc20.FormattedOptionParts;
import ee.cyber.cdoc20.cli.SymmetricKeyUtil;
import ee.cyber.cdoc20.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.util.SkLdapUtil;
import ee.cyber.cdoc20.util.Resources;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;

import java.io.File;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

//S106 - Standard outputs should not be used directly to log anything
//CLI needs to interact with standard outputs
@SuppressWarnings("java:S106")
@Command(name = "create", aliases = {"c", "encrypt"}, showAtFileInUsageHelp = true)
public class CDocCreateCmd implements Callable<Void> {
    private static final Logger log = LoggerFactory.getLogger(CDocCreateCmd.class);

    // default server configuration disabled, until public key server is up and running
    //private static final String DEFAULT_SERVER_PROPERTIES = "classpath:localhost.properties";

    @Option(names = {"-f", "--file" }, required = true, paramLabel = "CDOC", description = "the CDOC2.0 file")
    File cdocFile;

    // one of cert or pubkey must be specified
    @CommandLine.ArgGroup(exclusive = false, multiplicity = "1..*")
    Dependent recipient;

    static class Dependent {
        @Option(names = {"-p", "--pubkey"},
                paramLabel = "PEM", description = "recipient public key in PEM format")
        File[] pubKeys;

        @Option(names = {"-c", "--cert"},
                paramLabel = "CER", description = "recipient x509 certificate in DER or PEM format")
        File[] certs;

        @Option(names = {"-r", "--recipient", "--receiver"},
                paramLabel = "isikukood", description = "recipient id code (isikukood)")
        String[] identificationCodes;

        @Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
                description = SymmetricKeyUtil.SECRET_DESCRIPTION)
        String[] secrets;

        @Option(names = {"-pass", "--password"}, arity = "0..1",
            paramLabel = "<label>:<password>", description = SymmetricKeyUtil.PASSWORD_DESCRIPTION)
        String password;
    }

    // allow -Dkey for setting System properties
    @Option(names = "-D", mapFallbackValue = "", description = "Set Java System property")
    void setProperty(Map<String, String> props) {
        props.forEach(System::setProperty);
    }

    @Option(names = {"-S", "--server"},
            paramLabel = "FILE.properties",
            description = "Key server connection properties file"
            // default server configuration disabled, until public key server is up and running
            //, arity = "0..1"
            //, fallbackValue = DEFAULT_SERVER_PROPERTIES
    )
    String keyServerPropertiesFile;

    @Parameters(paramLabel = "FILE", description = "one or more files to encrypt", arity = "1..*")
    File[] inputFiles;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
    private boolean helpRequested = false;

    @Override
    public Void call() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("create --file {} --pubkey {} --cert {} {}",
                cdocFile,
                Arrays.toString(recipient.pubKeys),
                Arrays.toString(recipient.certs),
                Arrays.toString(inputFiles));
        }

        //Map of PublicKey, keyLabel
        Map<PublicKey, String> recipientsMap = new LinkedHashMap<>();

        recipientsMap.putAll(PemTools.loadPubKeysWithKeyLabel(this.recipient.pubKeys));
        recipientsMap.putAll(PemTools.loadCertKeysWithLabel(this.recipient.certs));

        // fetch authentication certificates' public keys for natural person identity codes
        Map<PublicKey, String> ldapKeysWithLabels =
                SkLdapUtil.getPublicKeysWithLabels(this.recipient.identificationCodes).entrySet()
                    .stream()
                    .filter(entry -> EllipticCurve.isSupported(entry.getKey()))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        recipientsMap.putAll(ldapKeysWithLabels);

        List<EncryptionKeyMaterial> recipients = recipientsMap.entrySet().stream()
                .map(entry -> EncryptionKeyMaterial.fromPublicKey(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());

        addSymmetricKeysWithLabels(recipients);

        CDocBuilder cDocBuilder = new CDocBuilder()
            .withRecipients(recipients)
            .withPayloadFiles(Arrays.asList(inputFiles));

        if (keyServerPropertiesFile != null) {
            Properties p = new Properties();
            p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
            cDocBuilder.withServerProperties(p);
        }

        cDocBuilder.buildToFile(cdocFile);

        log.info("Created {}", cdocFile.getAbsolutePath());

        return null;
    }

    private void addSymmetricKeysWithLabels(List<EncryptionKeyMaterial> recipients)
        throws CDocValidationException {

        recipients.addAll(SymmetricKeyUtil.extractEncryptionKeyMaterialFromSecrets(
            recipient.secrets)
        );
        if (null != recipient.password) {
            FormattedOptionParts password
                = SymmetricKeyUtil.getSplitPasswordAndLabel(recipient.password);
            recipients.add(SymmetricKeyUtil.extractEncryptionKeyMaterialFromPassword(password));
        }
    }

}
