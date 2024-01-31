package ee.cyber.cdoc20.crypto.keymaterial;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;


/**
 * Represents key material required for decryption with symmetric key derived from secret.
 *
 * @param keyLabel  key label
 * @param secretKey symmetric key
 */
public record SecretDecryptionKeyMaterial(
    String keyLabel,
    SecretKey secretKey
) implements DecryptionKeyMaterial, Destroyable {

    @Override
    public Object getRecipientId() {
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.FROM_SECRET;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        secretKey.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return secretKey.isDestroyed();
    }

    /**
     * Symmetric Key used by Symmetric Key scenario
     * @return SecretKey secret key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

}
