package ee.cyber.cdoc2.converter.util;

import ee.cyber.cdoc2.converter.util.PasswordCheckUtil;
import ee.cyber.cdoc2.converter.util.Util;

import java.io.File;
import java.util.Arrays;

public final class CommonService {

    private CommonService() {}

    public static char[] askPassword() throws Exception {

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

        return password;
    }

    public static String getLabel(String labelOption) throws Exception {
        String label = (labelOption != null) ? labelOption : Util.genPwLabel();
        if (labelOption == null) {
            System.out.println("Generated CDOC2 label: " + label);
        }

        return label;
    }

    public static File getCdoc2File(File cdoc2FileOption, File incomingFile) {
        return (cdoc2FileOption != null) ? cdoc2FileOption: Util.genCDoc2Filename(incomingFile);
    }
}