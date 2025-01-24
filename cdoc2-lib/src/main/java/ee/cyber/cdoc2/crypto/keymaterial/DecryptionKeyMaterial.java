package ee.cyber.cdoc2.crypto.keymaterial;

import java.security.KeyPair;
import javax.crypto.SecretKey;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyShareDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.PasswordDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SecretDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;


/**
 * Represents key material required for decryption.
 */
public interface DecryptionKeyMaterial {

    /**
     * Uniquely identifies the recipient. This data is used to find recipients key material from parsed CDOC header
     * <ul>
     * <li> For EC, this is EC pub key.
     * <li> For RSA, this is RSA pub key
     * <li> For SymmetricKey, this is keyLabel
     * <li> For Authentication means, this string {identifier-type}/{identifier}.
     *      For SID/MID this in format 'etsi/{SemanticesIdentifier}' e.g. etsi/PNOEE-48010010101
     * </ul>
     * @return Object that uniquely identifies Recipient
     */
    Object getRecipientId();

    /**
     * Identifies the origin of key derivation. This data is used to find the correct
     * decryption algorithm.
     * @return EncryptionKeyOrigin encryption key origin
     */
    EncryptionKeyOrigin getKeyOrigin();

    /**
     * Creates decryption key material with secret key.
     * @param secretKey secret key
     * @param label key label
     * @return DecryptionKeyMaterial key material required for decryption
     */
    static DecryptionKeyMaterial fromSecretKey(SecretKey secretKey, String label) {
        return new SecretDecryptionKeyMaterial(secretKey, label);
    }

    static DecryptionKeyMaterial fromPassword(char[] password, String label) {
        return new PasswordDecryptionKeyMaterial(password, label);
    }

    static DecryptionKeyMaterial fromKeyPair(KeyPair recipientKeyPair) {
        return new KeyPairDecryptionKeyMaterial(recipientKeyPair);
    }

    static DecryptionKeyMaterial fromAuthMeans(
        AuthenticationIdentifier authIdentifier
    ) {
        return new KeyShareDecryptionKeyMaterial(authIdentifier);
    }

}
