package ee.cyber.cdoc2.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.CDocValidationException;
import ee.cyber.cdoc2.FormattedOptionParts;
import ee.cyber.cdoc2.container.CDocParseException;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.SymmetricKeyTools;
import ee.cyber.cdoc2.util.PasswordValidationUtil;

import javax.annotation.Nullable;


/**
 * Symmetric key usage in CDOC is supported by CDOC format, but its use cases are not finalized.
 * In the future, symmetric key may be derived using password-based key-derivation algorithm or from hardware token.
 * For now, symmetric key can be provided directly from the command line (or from a file with @option)
 */
public final class SymmetricKeyUtil {

    public static final String BASE_64_PREFIX = "base64,";

    public static final String LABEL_LOG_MSG = "Label for symmetric key: {}";

    private static final String SYMMETRIC_KEY_DESCRIPTION = "symmetric key with label. "
        + "Must have format";

    private static final String PW_DESCRIPTION = "password with label. Must have format";

    // --secret format description, used in cdoc <cmd> classes
    public static final String SECRET_DESCRIPTION = SYMMETRIC_KEY_DESCRIPTION
        + " <label>:<secret>. <secret> is a base64 encoded binary. "
        + "It must be prefixed with `base64,`";

    // --password format description, used in cdoc <cmd> classes
    public static final String PASSWORD_DESCRIPTION = PW_DESCRIPTION
        + " <label>:<password>. <password> can be plain text or base64 "
        + "encoded binary. In case of base64, it must be prefixed with `base64,`";

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
            FormattedOptionParts splitSecret
                = splitFormattedOption(secret, EncryptionKeyOrigin.SECRET);

            EncryptionKeyMaterial km
                = SymmetricKeyTools.getEncryptionKeyMaterialFromSecret(splitSecret);
            result.add(km);
        }
        return result;
    }

    public static EncryptionKeyMaterial extractEncryptionKeyMaterialFromSecret(
        String secret
    ) throws CDocValidationException {
        if (secret == null) {
            return null;
        }

        FormattedOptionParts splitSecret
            = splitFormattedOption(secret, EncryptionKeyOrigin.SECRET);

        return SymmetricKeyTools.getEncryptionKeyMaterialFromSecret(splitSecret);
    }

    public static EncryptionKeyMaterial extractEncryptionKeyMaterialFromPassword(
        FormattedOptionParts passwordAndLabel
    ) {
        return EncryptionKeyMaterial.fromPassword(
            passwordAndLabel.optionChars(), passwordAndLabel.label()
        );
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
        String optionName = keyOrigin.name();
        if (parts.length != 2) {
            throw new CDocValidationException(
                String.format("Option %s must have format label:value", optionName)
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
            excludeSecretKeyInPlainText(keyOrigin);
            optionChars = option.toCharArray();
            log.debug("Decoded {} bytes from {}", optionChars.length, optionName);
        }
        log.info(LABEL_LOG_MSG, label);

        return new FormattedOptionParts(optionChars, label, keyOrigin);
    }

    /**
     * Split formatted password "label:topsecret123!" or "label123:base64,
     * aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedPassword formatted as label:password where 2nd param can be base64 encoded
     *                          bytes or regular utf-8 string. Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string. If "",
     *                          then password and label are asked interactively.
     * @param verifyPw if password should be asked twice to verify that they match (encryption).
     * @return FormattedOptionParts with extracted password and label
     */
    public static FormattedOptionParts getSplitPasswordAndLabel(String formattedPassword,
                                                                boolean verifyPw)
        throws CDocValidationException {
        FormattedOptionParts passwordAndLabel;
        if (formattedPassword.isEmpty()) {
            passwordAndLabel = InteractiveCommunicationUtil.readPasswordAndLabelInteractively(verifyPw);
        } else {
            passwordAndLabel
                = splitFormattedOption(formattedPassword, EncryptionKeyOrigin.PASSWORD);

            if (verifyPw) {
                PasswordValidationUtil.validatePassword(passwordAndLabel.optionChars());
            }
        }

        return passwordAndLabel;
    }

    /**
     * Get password for decryption. Ignore user-entered label when there is only one pbkdf  (password) recipient
     * in CDOC2 header.
     * @param formattedPassword formatted as label:password where
     *                          2nd param can be base64 encoded bytes or regular utf-8 string.
     *                          Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string. If "",
     *                          then password and label are asked interactively.
     * @param pbkdf2Recipients if pbkdf2Recipients.size() == 1 then label is read from CDOC header
     * @return
     * @throws CDocValidationException
     */
    public static FormattedOptionParts getSplitPasswordAndLabel(String formattedPassword,
                                                                List<PBKDF2Recipient> pbkdf2Recipients)
        throws CDocValidationException {

        if (pbkdf2Recipients.size() == 1) {
            String label = pbkdf2Recipients.get(0).getRecipientKeyLabel();
            if (formattedPassword.isEmpty()) {
                char[] pw = InteractiveCommunicationUtil.readPasswordInteractively(System.console(),
                    InteractiveCommunicationUtil.PROMPT_PASSWORD);

                return new FormattedOptionParts(pw, label, EncryptionKeyOrigin.PASSWORD);
            } else {
                FormattedOptionParts parsed =
                    splitFormattedOption(formattedPassword, EncryptionKeyOrigin.PASSWORD);
                //overwrite label with recipient label to allow entering password without label for
                //single pbkdfRecipient eg -pw ":pw"
                return new FormattedOptionParts(parsed.optionChars(), label, EncryptionKeyOrigin.PASSWORD);
            }
        } else {
            return getSplitPasswordAndLabel(formattedPassword, false);
        }
    }

    /**
     * Extract decryption key material from formatted secret or password "label:topsecret123!"
     * or "label123:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param cDocFilePath      path to CDOC file
     * @param formattedPassword formatted as label:password where 2nd param can be base64 encoded
     *                          bytes or regular utf-8 string. Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string
     * @param formattedSecret   formatted as label:secret where 2nd param can be base64 encoded
     *                          bytes or regular utf-8 string. Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string
     * @return DecryptionKeyMaterial decryption key material
     * @throws CDocValidationException if formatted option is not in format specified
     * @throws GeneralSecurityException if decryption key material extraction from password has
     *                                  failed
     * @throws IOException if header parsing has failed
     * @throws CDocParseException if recipients deserializing has failed
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterial(
        Path cDocFilePath,
        @Nullable String formattedPassword,
        @Nullable String formattedSecret
    ) throws CDocValidationException,
        GeneralSecurityException,
        IOException,
        CDocParseException {

        List<Recipient> recipients = Envelope.parseHeader(Files.newInputStream(cDocFilePath));


        DecryptionKeyMaterial decryptionKm = null;
        if (null != formattedPassword) {
            List<PBKDF2Recipient> pbkdf2Recipients = recipients.stream()
                .filter(recipient -> recipient instanceof PBKDF2Recipient)
                .map(r -> (PBKDF2Recipient)r).toList();

            FormattedOptionParts splitPassword = getSplitPasswordAndLabel(formattedPassword, pbkdf2Recipients);
            decryptionKm =
                SymmetricKeyTools.extractDecryptionKeyMaterialFromPassword(splitPassword, recipients);
        }
        if (null != formattedSecret && null == decryptionKm) {
            FormattedOptionParts splitSecret = splitFormattedOption(
                formattedSecret, EncryptionKeyOrigin.SECRET
            );
            decryptionKm =
                SymmetricKeyTools.extractDecryptionKeyMaterialFromSecret(splitSecret, recipients);
        }

        return decryptionKm;
    }

    private static void excludeSecretKeyInPlainText(EncryptionKeyOrigin keyOrigin) {
        if (keyOrigin == EncryptionKeyOrigin.SECRET) {
            String errorMsg = "Secret must be as a base64 encoded value";
            log.error(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }

}
