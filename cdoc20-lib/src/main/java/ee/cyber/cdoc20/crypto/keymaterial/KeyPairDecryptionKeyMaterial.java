package ee.cyber.cdoc20.crypto.keymaterial;

import java.security.KeyPair;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;

/**
 * Represents key material required for decryption with key pair.
 *
 * @param recipientKeyPair recipient key pair
 */
public record KeyPairDecryptionKeyMaterial(
    KeyPair recipientKeyPair
) implements DecryptionKeyMaterial, Destroyable {

    @Override
    public Object getRecipientId() {
        return this.recipientKeyPair.getPublic();
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.FROM_PUBLIC_KEY;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        recipientKeyPair.getPrivate().destroy();
    }

    @Override
    public boolean isDestroyed() {
        return recipientKeyPair.getPrivate().isDestroyed();
    }

    /**
     * KeyPair used by EC and RSA scenario
     * @return KeyPair key pair
     */
    public KeyPair getKeyPair() {
        return this.recipientKeyPair;
    }

}
