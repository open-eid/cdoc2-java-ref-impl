package ee.cyber.cdoc20.cli;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for password validation.
 */
public final class PasswordValidationUtil {

    private static final int PW_MAX_LENGTH = 64;
    private static final int PW_MIN_LENGTH = 8;
    private static final String REGEX = "(?=.*[a-z])" // a lower case alphabet must occur at least once
        + "(?=.*[A-Z])" // an upper case alphabet that must occur at least once
        + ".{" + PW_MIN_LENGTH + "," + PW_MAX_LENGTH + "}" // allowed length range
        + "$";

    private static final String PW_REQUIREMENTS = "Password length should be between "
        + PW_MIN_LENGTH + " and " + PW_MAX_LENGTH
        + ", should contain at least one upper case or one lower case character";

    private PasswordValidationUtil() { }

    private static final Logger log = LoggerFactory.getLogger(PasswordValidationUtil.class);


    public static void validatePassword(char[] password) {
        if (!passwordMatches(String.valueOf(password))) {
            log.error(PW_REQUIREMENTS);
            throw new IllegalArgumentException(PW_REQUIREMENTS);
        }
    }

    private static boolean passwordMatches(String password) {
        Pattern pattern = Pattern.compile(REGEX);
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

}
