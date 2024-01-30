package ee.cyber.cdoc20.crypto.keymaterial;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import ee.cyber.cdoc20.crypto.Crypto;

/**
 * Represents key material required for encryption.
 */
public interface EncryptionKeyMaterial extends Destroyable {

    /**
     * @return the key to derive the encryption key
     */
    Key getKey();

    /**
     * @return identifier for the encryption key
     */
    String getLabel();

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel. To decrypt CDOC, recipient must have
     * the private key part of the public key. RSA and EC public keys are supported by CDOC.
     * @param publicKey public key
     * @param keyLabel  key label
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromPublicKey(PublicKey publicKey, String keyLabel) {
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return publicKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }

            @Override
            public void destroy() {
                // no secret key material that needs to be destroyed
            }
        };
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
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return preSharedKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }

            @Override
            public void destroy() throws DestroyFailedException {
                preSharedKey.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return preSharedKey.isDestroyed();
            }
        };
    }

    /**
     * Create PasswordDerivedEncryptionKeyMaterial from password.
     * To decrypt CDOC, recipient must also have same preSharedKey and salt that are identified by
     * the same keyLabel
     * @param password password chars for extracting pre-shared SecretKey
     * @param keyLabel unique identifier for preSharedKey
     * @return PasswordDerivedEncryptionKeyMaterial object
     */
    static PasswordEncryptionKeyMaterial fromPassword(
        char[] password, String keyLabel
    ) throws GeneralSecurityException {
        byte[] passwordSalt = Crypto.generateSaltForKey();
        SecretKey preSharedKey = Crypto.extractSymmetricKeyFromPassword(password, passwordSalt);

        return new PasswordEncryptionKeyMaterial(
            preSharedKey,
            keyLabel,
            passwordSalt
        ) {
            @Override
            public void destroy() throws DestroyFailedException {
                preSharedKey.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return preSharedKey.isDestroyed();
            }
        };
    }

}
