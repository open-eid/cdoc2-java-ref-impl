package ee.cyber.cdoc20.crypto.keymaterial;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;


/**
 * Represents key material required for decryption with symmetric key derived from secret.
 */
public class SecretDecryptionKeyMaterial implements DecryptionKeyMaterial, Destroyable {

    private final String keyLabel;
    private final SecretKey secretKey;

    public SecretDecryptionKeyMaterial(String keyLabel, SecretKey secretKey) {
        this.keyLabel = keyLabel;
        this.secretKey = secretKey;
    }

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
