package ee.cyber.cdoc20.cli;

import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;
import org.passay.PasswordValidator;
import org.passay.RuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Utility class for password validation.
 */
public final class PasswordValidationUtil {

    private static final int PW_MAX_LENGTH = 64;
    private static final int PW_MIN_LENGTH = 8;

    private static final String PW_REQUIREMENTS = "Password length should be between "
        + PW_MIN_LENGTH + " and " + PW_MAX_LENGTH
        + ", should contain at least one upper case or one lower case character";

    private PasswordValidationUtil() { }

    private static final Logger log = LoggerFactory.getLogger(PasswordValidationUtil.class);

    public static void validatePassword(char[] password) {
        if (!passwordIsValid(String.valueOf(password))) {
            log.error(PW_REQUIREMENTS);
            throw new IllegalArgumentException(PW_REQUIREMENTS);
        }
    }

    private static boolean passwordIsValid(String password) {
        return getValidationRules(password).isValid();
    }

    private static RuleResult getValidationRules(String password) {
        PasswordValidator validator = configureValidationRules();
        PasswordData passwordData = new PasswordData(password);
        return validator.validate(passwordData);
    }

    private static PasswordValidator configureValidationRules() {
        return new PasswordValidator(
            new LengthRule(PW_MIN_LENGTH, PW_MAX_LENGTH),
            new CharacterRule(EnglishCharacterData.LowerCase, 1),
            new CharacterRule(EnglishCharacterData.UpperCase, 1)
        );
    }

}
