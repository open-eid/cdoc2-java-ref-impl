package ee.cyber.cdoc20.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc20.CDocValidationException;
import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc20.container.recipients.Recipient;
import ee.cyber.cdoc20.container.recipients.SymmetricKeyRecipient;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;


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
            FormattedOptionParts splitSecret
                = SymmetricKeyUtil.splitFormattedOption(secret, EncryptionKeyOrigin.FROM_SECRET);
            var entry = extractKeyMaterialFromSecret(splitSecret);
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
        byte[] salt = Crypto.generateSaltForKey();
        SecretKey secretKey = Crypto.extractKeyMaterialFromPassword(
            passwordAndLabel.optionChars(), salt
        );
        return EncryptionKeyMaterial.fromPassword(
            secretKey, passwordAndLabel.label(), passwordAndLabel.keyOrigin(), salt
        );
    }

    /**
     * Extract symmetric key material from secret.
     * @param secretAndLabel split secret chars and label
     * @return DecryptionKeyMaterial created from formattedSecret
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromSecret(
        FormattedOptionParts secretAndLabel
    ) {
        var entry = extractKeyMaterialFromSecret(secretAndLabel);
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
        SecretKey secretKey = Crypto.extractKeyMaterialFromPassword(
            passwordAndLabel.optionChars(), salt
        );

        return DecryptionKeyMaterial.fromPassword(passwordAndLabel.label(), secretKey, salt);
    }

    /**
     * Extract symmetric key material from secret.
     * @param secretAndLabel split secret and label
     * @return AbstractMap.SimpleEntry<SecretKey, String> with extracted SecretKey and label
     */
    private static AbstractMap.SimpleEntry<SecretKey, String> extractKeyMaterialFromSecret(
        FormattedOptionParts secretAndLabel
    ) {
        byte[] secretBytes = String.valueOf(secretAndLabel.optionChars())
            .getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(secretBytes, "");
        return new AbstractMap.SimpleEntry<>(key, secretAndLabel.label());
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

    /**
     * Split formatted password "label:topsecret123!" or "label123:base64,
     * aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
     * @param formattedPassword formatted as label:password where 2nd param can be base64 encoded
     *                          bytes or regular utf-8 string. Base64 encoded string must be
     *                          prefixed with 'base64,', followed by base64 string
     * @return FormattedOptionParts with extracted password and label
     */
    public static FormattedOptionParts getSplitPasswordAndLabel(String formattedPassword)
        throws CDocValidationException {
        FormattedOptionParts passwordAndLabel;
        if (formattedPassword.isEmpty()) {
            passwordAndLabel = InteractiveCommunicationUtil.readPasswordAndLabelInteractively();
        } else {
            passwordAndLabel
                = splitFormattedOption(formattedPassword, EncryptionKeyOrigin.FROM_PASSWORD);
        }

        // ToDo add password validation somewhere here #55910

        return passwordAndLabel;
    }

    /**
     * Extract symmetric key material from formatted secret or password "label:topsecret123!"
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
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromSymmetricKey(
        Path cDocFilePath,
        String formattedPassword,
        String formattedSecret
    ) throws CDocValidationException,
        GeneralSecurityException,
        IOException,
        CDocParseException {

        List<Recipient> recipients = Envelope.parseHeader(Files.newInputStream(cDocFilePath));
        for (Recipient recipient : recipients) {
            if (recipient instanceof PBKDF2Recipient pbkdf2Recipient && formattedPassword != null) {
                FormattedOptionParts splitPassword
                    = SymmetricKeyUtil.getSplitPasswordAndLabel(formattedPassword);
                byte[] salt = pbkdf2Recipient.getSalt();

                return SymmetricKeyUtil.extractDecryptionKeyMaterialFromPassword(
                    splitPassword, salt
                );
            } else if (recipient instanceof SymmetricKeyRecipient && formattedSecret != null) {
                FormattedOptionParts splitSecret = SymmetricKeyUtil.splitFormattedOption(
                    formattedSecret, EncryptionKeyOrigin.FROM_SECRET
                );
                if (recipient.getRecipientKeyLabel().equals(splitSecret.label())) {
                    return SymmetricKeyUtil.extractDecryptionKeyMaterialFromSecret(splitSecret);
                }
            }
        }
        return null;
    }

}
