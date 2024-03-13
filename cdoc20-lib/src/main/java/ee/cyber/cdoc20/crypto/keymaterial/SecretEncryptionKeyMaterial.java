package ee.cyber.cdoc20.crypto.keymaterial;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;

/**
 * Represents key material required for encryption with symmetric key derived from secret.
 *
 * @param preSharedKey pre-shared symmetric key
 * @param keyLabel     key label
 */
public record SecretEncryptionKeyMaterial(
    SecretKey preSharedKey,
    String keyLabel
) implements EncryptionKeyMaterial, Destroyable {

    @Override
    public String getLabel() {
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.SECRET;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        preSharedKey.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return preSharedKey.isDestroyed();
    }

    /**
     * @return symmetric key to derive the encryption key
     */
    public SecretKey getSecretKey() {
        return preSharedKey;
    }

}
