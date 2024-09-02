package ee.cyber.cdoc2.crypto;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.container.recipients.SymmetricKeyRecipient;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.FormattedOptionParts;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.getPlainKeyLabel;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.isFormatted;


/**
 * Utility for deriving Symmetric key from secret or password
 */
public final class SymmetricKeyTools {

    private SymmetricKeyTools() { }

    /**
     * Extract decryption key material from password.
     * @param pwAndLabel split password and label
     * @param recipients       the list of recipients
     * @return DecryptionKeyMaterial created from password
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromPassword(
        FormattedOptionParts pwAndLabel,
        List<Recipient> recipients
    ) {
        for (Recipient recipient : recipients) {
            if (keyLabelMatches(recipient, EncryptionKeyOrigin.PASSWORD, pwAndLabel.label())) {
                return DecryptionKeyMaterial.fromPassword(
                    pwAndLabel.optionChars(),
                    recipient.getRecipientKeyLabel()
                );
            }
        }
        return null;
    }

    /**
     * Extract decryption key material from secret.
     * @param secretAndLabel split secret and label
     * @param recipients     the list of recipients
     * @return DecryptionKeyMaterial created from secret
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromSecret(
        FormattedOptionParts secretAndLabel,
        List<Recipient> recipients
    ) {
        for (Recipient recipient : recipients) {
            if (keyLabelMatches(recipient, EncryptionKeyOrigin.SECRET, secretAndLabel.label())) {
                var entry = extractKeyMaterialFromSecret(secretAndLabel);
                return DecryptionKeyMaterial.fromSecretKey(
                    entry.getKey(), recipient.getRecipientKeyLabel()
                );
            }
        }
        return null;
    }

    /**
     * Extract symmetric key material from secret.
     * @param secretAndLabel split secret and label
     * @return AbstractMap.SimpleEntry<SecretKey, String> with extracted SecretKey and label
     */
    public static AbstractMap.SimpleEntry<SecretKey, String> extractKeyMaterialFromSecret(
        FormattedOptionParts secretAndLabel
    ) {
        byte[] secretBytes = String.valueOf(secretAndLabel.optionChars())
            .getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES) {
            throw new IllegalArgumentException("min len is " + Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES);
        }
        SecretKey key = new SecretKeySpec(secretBytes, "");
        return new AbstractMap.SimpleEntry<>(key, secretAndLabel.label());
    }

    /**
     * Extract symmetric key material from secret.
     * @param secretAndLabel split secret and label
     * @return EncryptionKeyMaterial with extracted SecretKey and label
     */
    public static EncryptionKeyMaterial getEncryptionKeyMaterialFromSecret(
        FormattedOptionParts secretAndLabel
    ) {
        var entry = extractKeyMaterialFromSecret(secretAndLabel);
        return EncryptionKeyMaterial.fromSecret(entry.getKey(), entry.getValue());
    }

    public static EncryptionKeyMaterial getEncryptionKeyMaterialFromPassword(
        FormattedOptionParts splitPasswordAndLabel
    ) {
        return EncryptionKeyMaterial.fromPassword(splitPasswordAndLabel.optionChars(), splitPasswordAndLabel.label());
    }

    private static boolean keyLabelMatches(
        Recipient recipient,
        EncryptionKeyOrigin keyOrigin,
        String requestedKeyLabel
    ) {
        String recipientKeyLabel = recipient.getRecipientKeyLabel();
        String plainKeyLabel = getPlainKeyLabel(recipientKeyLabel);
        if (EncryptionKeyOrigin.PASSWORD == keyOrigin) {
            return passwordKeyLabelMatches(recipient, plainKeyLabel, requestedKeyLabel);
        } else if (EncryptionKeyOrigin.SECRET == keyOrigin) {
            return recipient instanceof SymmetricKeyRecipient
                && plainKeyLabel.equals(requestedKeyLabel);
        }
        return false;
    }

    private static boolean passwordKeyLabelMatches(
        Recipient recipient,
        String plainKeyLabel,
        String requestedKeyLabel
    ) {
        if (isFormatted(requestedKeyLabel)) {
            return recipient instanceof PBKDF2Recipient
                && recipient.getRecipientKeyLabel().equals(requestedKeyLabel);
        }
        return recipient instanceof PBKDF2Recipient && plainKeyLabel.equals(requestedKeyLabel);
    }

}
