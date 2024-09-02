package ee.cyber.cdoc2.cli.util;

import java.io.Console;
import java.util.Arrays;
import javax.swing.*;

import ee.cyber.cdoc2.crypto.keymaterial.LabeledPassword;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.CDocUserException;
import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.util.PasswordValidationUtil;

import static ee.cyber.cdoc2.cli.util.CliConstants.LABEL_LOG_MSG;


/**
 * Utility class for asking password or label interactively.
 */
public final class InteractiveCommunicationUtil {

    private static final Logger log = LoggerFactory.getLogger(InteractiveCommunicationUtil.class);

    public static final String PROMPT_LABEL = "Please enter label: ";
    public static final String PROMPT_PASSWORD = "Password is missing. Please enter: ";
    public static final String PROMPT_PASSWORD_REENTER = "Re-enter password: ";

    private InteractiveCommunicationUtil() { }

    /**
     * Ask password and label interactively.
     * @param verifyPw if true then password is asked twice and they must match
     * @return FormattedOptionParts with password chars and label
     * @throws CDocUserException if password wasn't entered
     * @throws IllegalArgumentException if entered passwords don't match
     */
    public static LabeledPassword readPasswordAndLabelInteractively(boolean verifyPw) {
        return doReadPasswordAndLabelInteractively(verifyPw, true);
    }

    public static LabeledPassword readOnlyPasswordInteractively(boolean verifyPw) {
        return doReadPasswordAndLabelInteractively(verifyPw, false);
    }

    private static LabeledPassword doReadPasswordAndLabelInteractively(boolean verifyPw, boolean readLabel) {
        Console console = System.console();
        char[] password = readPasswordInteractively(console, PROMPT_PASSWORD);
        PasswordValidationUtil.validatePassword(password);

        if (verifyPw) {
            char[] reenteredPassword = readPasswordInteractively(console, PROMPT_PASSWORD_REENTER);

            if (!Arrays.equals(password, reenteredPassword)) {
                log.info("Passwords don't match");
                throw new IllegalArgumentException("Passwords don't match");
            }
        }

        String label = (readLabel) ? readLabelInteractively(console) : "";

        return new LabeledPassword() {
            @Override
            public String getLabel() {
                return label;
            }

            @Override
            public char[] getPassword() {
                return password;
            }
        };
    }

    public static char[] readPasswordInteractively(Console console, String prompt) throws CDocUserException {
        if (console != null) {
            return console.readPassword(prompt);
        } else { //running from IDE, console is null
            JPasswordField passField = new JPasswordField();
            int result = JOptionPane.showConfirmDialog(
                null,
                passField,
                prompt,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
            );

            if (result == JOptionPane.OK_OPTION) {
                return passField.getPassword();
            } else if (result == JOptionPane.OK_CANCEL_OPTION) {
                log.info("Password enter is cancelled");
                throw new CDocUserException(
                    UserErrorCode.USER_CANCEL, "Password entry cancelled by user"
                );
            } else {
                log.info("Password is not entered");
                throw new CDocUserException(UserErrorCode.USER_CANCEL, "Password not entered");
            }
        }
    }

    private static String readLabelInteractively(Console console) {
        if (console != null) {
            String label = console.readLine(PROMPT_LABEL);
            log.info(LABEL_LOG_MSG, label);
            return label;
        } else { //running from IDE, console is null
            JFrame labelField = new JFrame();
            String label = JOptionPane.showInputDialog(
                labelField,
                PROMPT_LABEL
            );
            log.info(LABEL_LOG_MSG, label);
            if (label == null || label.isBlank()) {
                throw new CDocUserException(UserErrorCode.USER_CANCEL, "Label not entered");
            }

            return label;
        }
    }

}
