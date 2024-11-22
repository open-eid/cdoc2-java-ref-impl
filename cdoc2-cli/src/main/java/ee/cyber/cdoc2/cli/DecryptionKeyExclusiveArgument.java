package ee.cyber.cdoc2.cli;

import picocli.CommandLine;

import java.io.File;

import ee.cyber.cdoc2.cli.util.CliConstants;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParam;
import ee.cyber.cdoc2.cli.util.LabeledPasswordParamConverter;
import ee.cyber.cdoc2.cli.util.LabeledSecretConverter;
import ee.cyber.cdoc2.crypto.keymaterial.LabeledSecret;


/**
 * Optional group of mutually exclusive arguments, only one of the arguments in the group can
 * appear on the command line
 */
public class DecryptionKeyExclusiveArgument {

    @CommandLine.Option(names = {"-k", "--key"},
        paramLabel = "PEM", description = "EC private key PEM used to decrypt")
    private File privKeyFile;

    @CommandLine.Option(names = {"-p12"},
        paramLabel = ".p12", description = "Load private key from .p12 file (FILE.p12:password)")
    private String p12;

    @CommandLine.Option(names = {"-s", "--secret"}, paramLabel = "<label>:<secret>",
        converter = LabeledSecretConverter.class,
        description = CliConstants.SECRET_DESCRIPTION)
    private LabeledSecret secret;

    @CommandLine.Option(names = {"-pw", "--password"}, arity = "0..1",
        converter = LabeledPasswordParamConverter.class,
        paramLabel = "<label>:<password>", description = CliConstants.PASSWORD_DESCRIPTION)
    // if empty --pw was provided labeledPasswordParam.isEmpty() is true
    // if option was not provided then labeledPasswordParam is null
    private LabeledPasswordParam labeledPasswordParam;

    @CommandLine.Option(names = {"-sid", "--smart-id"},
        paramLabel = "SID", description = "ID code for smart-id decryption")
    private String sid;

    @CommandLine.Option(names = {"-mid", "--mobile-id"},
        paramLabel = "MID", description = "ID code for mobile-id decryption")
    private String mid;

    public File getPrivKeyFile() {
        return this.privKeyFile;
    }

    public String getP12() {
        return this.p12;
    }

    public LabeledSecret getSecret() {
        return this.secret;
    }

    public LabeledPasswordParam getLabeledPasswordParam() {
        return this.labeledPasswordParam;
    }

    public boolean isWithSid() {
        return this.sid != null;
    }

    public boolean isWithMid() {
        return this.mid != null;
    }

    public String getSid() {
        return this.sid;
    }

    public String getMid() {
        return this.mid;
    }

}
