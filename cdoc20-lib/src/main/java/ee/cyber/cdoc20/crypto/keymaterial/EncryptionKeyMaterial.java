package ee.cyber.cdoc20.crypto.keymaterial;

import java.security.PublicKey;
import javax.crypto.SecretKey;

import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;


/**
 * Represents key material required for encryption.
 */
public interface EncryptionKeyMaterial {

    /**
     * @return identifier for the encryption key
     */
    String getLabel();

    /**
     * Identifies the origin of key derivation. This data is used to find the correct
     * encryption algorithm.
     * @return EncryptionKeyOrigin encryption key origin
     */
    EncryptionKeyOrigin getKeyOrigin();

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel. To decrypt CDOC, recipient must have
     * the private key part of the public key. RSA and EC public keys are supported by CDOC.
     * @param publicKey public key
     * @param keyLabel  key label
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromPublicKey(PublicKey publicKey, String keyLabel) {
        return new PublicKeyEncryptionKeyMaterial(publicKey, keyLabel);
    }

    /**
     * Create EncryptionKeyMaterial from secret.
     * To decrypt CDOC, recipient must also have same preSharedKey that is identified by the same
     * keyLabel
     * @param preSharedKey preSharedKey will be used to generate key encryption key
     * @param keyLabel     unique identifier for preSharedKey
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromSecret(SecretKey preSharedKey, String keyLabel) {
        return new SecretEncryptionKeyMaterial(preSharedKey, keyLabel);
    }

    /**
     * Create PasswordEncryptionKeyMaterial from password.
     * To decrypt CDOC, recipient must also have same preSharedKey and salt that are identified by
     * the same keyLabel
     * @param password password chars for extracting pre-shared SecretKey
     * @param keyLabel unique identifier for preSharedKey
     * @return PasswordEncryptionKeyMaterial object
     */
    static PasswordEncryptionKeyMaterial fromPassword(
        char[] password, String keyLabel
    ) {
        return new PasswordEncryptionKeyMaterial(password, keyLabel);
    }

}
