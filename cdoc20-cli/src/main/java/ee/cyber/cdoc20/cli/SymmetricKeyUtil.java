package ee.cyber.cdoc20.cli;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc20.CDocUserException;
import ee.cyber.cdoc20.CDocValidationException;
import ee.cyber.cdoc20.UserErrorCode;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;

import static ee.cyber.cdoc20.crypto.Crypto.MIN_SALT_LENGTH;

/**
 * Symmetric key usage in CDOC is supported by CDOC format, but its use cases are not finalized.
 * In the future, symmetric key may be derived using password-based key-derivation algorithm or from hardware token.
 * For now, symmetric key can be provided directly from the command line (or from a file with @option)
 */
public final class SymmetricKeyUtil {

    public static final String BASE_64_PREFIX = "base64,";

    public static final String LABEL_LOG_MSG = "Label for symmetric key: {}";

    public static final String PROMPT_LABEL = "Please enter label: ";
    public static final String PROMPT_PASSWORD = "Password is missing. Please enter: ";
    public static final String PROMPT_PASSWORD_REENTER = "Re-enter password: ";

    private static final String SYMMETRIC_KEY_DESCRIPTION = "symmetric key with label. "
        + "Must have format";
    private static final String SYMMETRIC_KEY_FORMAT_DETAILS = "can be plain text or base64 "
        + "encoded binary. In case of base64, it must be prefixed with `base64,`";

    // --secret format description, used in cdoc <cmd> classes
    public static final String SECRET_DESCRIPTION = SYMMETRIC_KEY_DESCRIPTION
        + " <label>:<secret>. <secret> " + SYMMETRIC_KEY_FORMAT_DETAILS;

    // --password format description, used in cdoc <cmd> classes
    public static final String PASSWORD_DESCRIPTION = SYMMETRIC_KEY_DESCRIPTION
        + " <label>:<password>. <password> " + SYMMETRIC_KEY_FORMAT_DETAILS;

    private SymmetricKeyUtil() { }

    private static final Logger log = LoggerFactory.getLogger(SymmetricKeyUtil.class);

    public static List<EncryptionKeyMaterial> extractEncryptionKeyMaterialFromSecrets(
        String[] secrets
    ) throws CDocValidationException {
        if (secrets == null || secrets.length == 0) {
            return List.of();
        }

        List<EncryptionKeyMaterial> result = new LinkedList<>();

        for (String secret: secrets) {
            var entry = extractKeyMaterialFromSecret(secret);
            EncryptionKeyMaterial km = EncryptionKeyMaterial.fromSecret(
                entry.getKey(), entry.getValue(), EncryptionKeyOrigin.FROM_SECRET
            );
            result.add(km);
        }
        return result;
    }

    public static EncryptionKeyMaterial extractEncryptionKeyMaterialFromPassword(
        FormattedOptionParts passwordAndLabel
    ) throws GeneralSecurityException {
        // ToDo replace salt via Crypto.generateSaltForKey() after extracting it for decryption flow
        byte[] salt = passwordAndLabel.label().getBytes(StandardCharsets.UTF_8);
        SecretKey secretKey = Crypto.deriveKekFromPassword(
            passwordAndLabel.optionChars(), salt
        );
        return EncryptionKeyMaterial.fromPassword(
            secretKey, passwordAndLabel.label(), passwordAndLabel.keyOrigin(), salt
        );
    }

    /**
     * Extract symmetric key material from formatted secret  "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedSecret formatted as label:secret where secret can be base64 encoded bytes or
     *                        regular utf-8 string. Base64 encoded string must be prefixed with
     *                        'base64,', followed by base64 string
     * @return DecryptionKeyMaterial created from formattedSecret
     * @throws CDocValidationException if formattedSecret is not in format specified
     * @throws IllegalArgumentException if base64 secret cannot be decoded
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterial(String formattedSecret)
            throws CDocValidationException {

        var entry = extractKeyMaterialFromSecret(formattedSecret);
        return DecryptionKeyMaterial.fromSecretKey(entry.getValue(), entry.getKey());
    }

    /**
     * Extract symmetric key material from password and salt.
     * @param passwordAndLabel split password chars and label
     * @param salt             salt used for encryption
     * @return DecryptionKeyMaterial created from password
     * @throws GeneralSecurityException if key extraction from password has failed
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromPassword(
        FormattedOptionParts passwordAndLabel, byte[] salt
    ) throws GeneralSecurityException {
        SecretKey secretKey = Crypto.deriveKekFromPassword(
            passwordAndLabel.optionChars(), salt
        );

        return DecryptionKeyMaterial.fromPassword(passwordAndLabel.label(), secretKey, salt);
    }

    public static FormattedOptionParts readPasswordAndLabelInteractively() {
        Console console = System.console();
        char[] password = readPasswordInteractively(console, PROMPT_PASSWORD);
        char[] reenteredPassword = readPasswordInteractively(console, PROMPT_PASSWORD_REENTER);

        // ToDo add full password validation here via separate method. #55910
        if (password.length == 0) {
            log.info("Password is not entered");
            throw new CDocUserException(UserErrorCode.USER_CANCEL, "Password not entered");
        }
        if (!Arrays.equals(password, reenteredPassword)) {
            log.info("Passwords don't match");
            throw new IllegalArgumentException("Passwords don't match");
        }

        String label = readLabelInteractively(console);

        return new FormattedOptionParts(password, label, EncryptionKeyOrigin.FROM_PASSWORD);
    }

    /**
     * Ask password interactively. If System.console() is available then password is red via
     * console. Otherwise, password is asked using GUI prompt.
     * @param prompt Prompt text to ask
     * @return chars of password entered by recipient
     * @throws CDocUserException if password finally wasn't entered
     */
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

    /**
     * Extract symmetric key material from formatted secret "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedSecret formatted as label:secret where secret can be base64 encoded bytes
     *                        or regular utf-8 string. Base64 encoded string must be prefixed with
     *                        'base64,', followed by base64 string
     * @return AbstractMap.SimpleEntry<SecretKey, String> with extracted SecretKey and label
     * @throws CDocValidationException if formattedSecret is not in format specified
     * @throws IllegalArgumentException if base64 secret cannot be decoded
     */
    private static AbstractMap.SimpleEntry<SecretKey, String> extractKeyMaterialFromSecret(
        String formattedSecret
    ) throws CDocValidationException {
        var splitOption
            = splitFormattedOption(formattedSecret, EncryptionKeyOrigin.FROM_SECRET);
        byte[] secretBytes = String.valueOf(splitOption.optionChars()).getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(secretBytes, "");
        return new AbstractMap.SimpleEntry<>(key, splitOption.label());
    }

    /**
     * Extract symmetric key material from formatted secret or password "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedOption formatted as label:secret or label:password where 2nd param can be
     *                        base64 encoded bytes or regular utf-8 string. Base64 encoded string
     *                        must be prefixed with 'base64,', followed by base64 string
     * @param keyOrigin       encryption key origin
     * @return AbstractMap.SimpleEntry<SecretKey, String> with extracted SecretKey and label
     * @throws CDocValidationException if formattedOption is not in format specified
     * @throws IllegalArgumentException if base64 secret or password cannot be decoded
     */
    public static FormattedOptionParts splitFormattedOption(
        String formattedOption,
        EncryptionKeyOrigin keyOrigin
    ) throws CDocValidationException {
        var parts = formattedOption.split(":");
        String optionName = keyOrigin.getKeyName();
        if (parts.length != 2) {
            throw new CDocValidationException(
                String.format("%s must have format label:%s", optionName, optionName)
            );
        }

        String label = parts[0];
        String option = parts[1];

        char[] optionChars;

        if (option.startsWith(BASE_64_PREFIX)) {
            byte[] optionBytes = Base64.getDecoder().decode(option.substring(BASE_64_PREFIX.length()));
            optionChars = Arrays.toString(optionBytes).toCharArray();
            log.debug("Decoded {} bytes from {} (base64)", optionChars.length, optionName);
        } else {
            optionChars = option.toCharArray();
            log.debug("Decoded {} bytes from {}", optionChars.length, optionName);
        }
        log.info(LABEL_LOG_MSG, label);

        return new FormattedOptionParts(optionChars, label, keyOrigin);
    }

    public static FormattedOptionParts getSplitPasswordAndLabel(String formattedPassword)
        throws CDocValidationException {
        FormattedOptionParts passwordAndLabel;
        if (formattedPassword.isEmpty()) {
            passwordAndLabel = readPasswordAndLabelInteractively();
        } else {
            passwordAndLabel = splitFormattedOption(formattedPassword, EncryptionKeyOrigin.FROM_PASSWORD);
        }

        // ToDo add password validation somewhere here #55910
        validatePasswordLabelLength(passwordAndLabel.label());

        return passwordAndLabel;
    }

    private static void validatePasswordLabelLength(String label) {
        if (label.length() < MIN_SALT_LENGTH) {
            String errorMsg = "Label for password must be at least " + MIN_SALT_LENGTH + " bytes";
            log.error(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }
}
