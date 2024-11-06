package ee.cyber.cdoc2.crypto.keymaterial.decrypt;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;


/**
 * Represents key material required for decryption with symmetric key derived from secret.
 * @param secretKey symmetric key
 * @param keyLabel key label
 */
public record SecretDecryptionKeyMaterial(
    SecretKey secretKey,
    String keyLabel
) implements DecryptionKeyMaterial, Destroyable {

    @Override
    public Object getRecipientId() {
        if (KeyLabelTools.isFormatted(keyLabel)) {
            return KeyLabelTools.extractKeyLabel(keyLabel);
        }
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.SECRET;
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
