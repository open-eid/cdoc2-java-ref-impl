package ee.cyber.cdoc2.cli;

import picocli.CommandLine;


/**
 * Arguments for Mobile ID decryption/re-encryption commands,
 * used inside {@link DecryptionKeyExclusiveArgument}
 */
public class MobileIdArguments {

    @CommandLine.Option(names = {"-mid", "--mobile-id"},
        paramLabel = "MID", description = "ID code for mobile-id decryption")
    private String mid;

    @CommandLine.Option(names = {"-mid-phone", "--mobile-id-phone"},
        paramLabel = "MID", description = "Phone number for mobile-id decryption")
    private String midPhone;

    public String getMid() {
        if (null != this.midPhone && null == this.mid) {
            throw new IllegalArgumentException("Required identity code must be present to process");
        }
        return this.mid;
    }

    public String getMidPhone() {
        if (null != this.mid && null == this.midPhone) {
            throw new IllegalArgumentException("Required phone number is missing");
        }
        return this.midPhone;
    }

}
