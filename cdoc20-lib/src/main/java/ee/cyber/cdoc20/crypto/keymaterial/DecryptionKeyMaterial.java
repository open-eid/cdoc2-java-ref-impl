package ee.cyber.cdoc20.crypto.keymaterial;

import java.security.KeyPair;
import javax.crypto.SecretKey;

import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;

/**
 * Represents key material required for decryption.
 */
public interface DecryptionKeyMaterial {

    /**
     * Uniquely identifies the recipient. This data is used to find recipients key material from parsed CDOC header
     * * For EC, this is EC pub key.
     * * For RSA, this is RSA pub key
     * * For SymmetricKey, this is keyLabel
     * @return Object that uniquely identifies Recipient
     */
    Object getRecipientId();

    /**
     * Identifies the origin of key derivation. This data is used to find the correct
     * decryption algorithm.
     * @return EncryptionKeyOrigin encryption key origin
     */
    EncryptionKeyOrigin getKeyOrigin();

    static DecryptionKeyMaterial fromSecretKey(String label, SecretKey secretKey) {
        return new SecretDecryptionKeyMaterial(label, secretKey);
    }

    static DecryptionKeyMaterial fromPassword(char[] password, String label) {
        return new PasswordDecryptionKeyMaterial(password, label);
    }

    static DecryptionKeyMaterial fromKeyPair(KeyPair recipientKeyPair) {
        return new KeyPairDecryptionKeyMaterial(recipientKeyPair);
    }

}
