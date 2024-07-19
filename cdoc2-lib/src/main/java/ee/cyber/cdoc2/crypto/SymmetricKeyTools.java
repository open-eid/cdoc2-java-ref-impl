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

import static ee.cyber.cdoc2.crypto.KeyLabelTools.checkKeyLabelFormatAndGet;


/**
 * Utility for deriving Symmetric key from secret or password
 */
public final class SymmetricKeyTools {

    private SymmetricKeyTools() { }

    /**
     * Extract decryption key material from password.
     * @param passwordAndLabel split password and label
     * @param recipients       the list of recipients
     * @return DecryptionKeyMaterial created from password
     */
    public static DecryptionKeyMaterial extractDecryptionKeyMaterialFromPassword(
        FormattedOptionParts passwordAndLabel,
        List<Recipient> recipients
    ) {
        for (Recipient recipient : recipients) {
            if (recipient instanceof PBKDF2Recipient) {

                return DecryptionKeyMaterial.fromPassword(
                    passwordAndLabel.optionChars(),
                    passwordAndLabel.label()
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
            Object decryptionKeyLabel = checkKeyLabelFormatAndGet(
                recipient.getRecipientKeyLabel(),
                secretAndLabel.label()
                );
            if (recipient instanceof SymmetricKeyRecipient
                && recipient.getRecipientKeyLabel().equals(decryptionKeyLabel)) {
                var entry = extractKeyMaterialFromSecret(secretAndLabel);
                return DecryptionKeyMaterial.fromSecretKey(decryptionKeyLabel.toString(), entry.getKey());
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

//    public static EncryptionKeyMaterial getEncryptionKeyMaterial(
//        AbstractMap.SimpleEntry<SecretKey, String> entry, String payloadFileName
//    ) {
//        return EncryptionKeyMaterial.builder()
//            .fromSecret(entry.getKey(), entry.getValue(), payloadFileName);
//    }

    public static EncryptionKeyMaterial getEncryptionKeyMaterialFromPassword(
        FormattedOptionParts splitPasswordAndLabel
    ) {
        return EncryptionKeyMaterial.fromPassword(splitPasswordAndLabel.optionChars(), splitPasswordAndLabel.label());
    }

}
