package ee.cyber.cdoc20.cli;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for password validation.
 */
public final class PasswordValidationUtil {

    private static final int PW_MIN_LENGTH = 8;
    private static final int PW_MAX_LENGTH = 64;
    private static final String PW_LEN_ERROR_MSG = "Password length must be between "
        + PW_MIN_LENGTH + " and " + PW_MAX_LENGTH;

    private PasswordValidationUtil() { }

    private static final Logger log = LoggerFactory.getLogger(PasswordValidationUtil.class);


    public static void validatePassword(char[] password) {
        validatePasswordLength(password);
    }

    private static void validatePasswordLength(char[] password) {
        if (password.length < PW_MIN_LENGTH || password.length > PW_MAX_LENGTH) {
            log.error(PW_LEN_ERROR_MSG);
            throw new IllegalArgumentException(PW_LEN_ERROR_MSG);
        }
    }

}
