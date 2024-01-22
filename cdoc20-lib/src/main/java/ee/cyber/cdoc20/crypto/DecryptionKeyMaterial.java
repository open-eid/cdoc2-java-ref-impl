package ee.cyber.cdoc20.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Optional;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * Represents key material required for decryption.
 */
public interface DecryptionKeyMaterial extends Destroyable {
    /**
     * Uniquely identifies the recipient. This data is used to find recipients key material from parsed CDOC header
     * * For EC, this is EC pub key.
     * * For RSA, this is RSA pub key
     * * For SymmetricKey, this is keyLabel
     * @return Object that uniquely identifies Recipient
     */
    Object getRecipientId();

    /**
     * KeyPair used by EC and RSA scenario
     * @return KeyPair if exists
     */
    default Optional<KeyPair> getKeyPair() {
        return Optional.empty();
    }

    /**
     * Symmetric Key used by Symmetric Key scenario
     * @return SecretKey if exists
     */
    default Optional<SecretKey> getSecretKey() {
        return Optional.empty();
    }

    static DecryptionKeyMaterial fromSecretKey(String label, SecretKey secretKey) {
        return new DecryptionKeyMaterial() {
            @Override
            public Object getRecipientId() {
                return label;
            }

            @Override
            public Optional<SecretKey> getSecretKey() {
                return Optional.of(secretKey);
            }

            @Override
            public void destroy() throws DestroyFailedException {
                secretKey.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return secretKey.isDestroyed();
            }
        };
    }

    static DecryptionKeyMaterial fromPassword(char[] password, String label, byte[] passwordSalt)
        throws GeneralSecurityException {

        SecretKey secretKey = Crypto.extractKeyMaterialFromPassword(password, passwordSalt);

        return new DecryptionKeyMaterial() {
            @Override
            public Object getRecipientId() {
                return label;
            }

            @Override
            public Optional<SecretKey> getSecretKey() {
                return Optional.of(secretKey);
            }

            @Override
            public void destroy() throws DestroyFailedException {
                secretKey.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return secretKey.isDestroyed();
            }
        };
    }

    static DecryptionKeyMaterial fromKeyPair(KeyPair recipientKeyPair) {
        return new DecryptionKeyMaterial() {
            @Override
            public Object getRecipientId() {
                return recipientKeyPair.getPublic();
            }

            @Override
            public Optional<KeyPair> getKeyPair() {
                return Optional.of(recipientKeyPair);
            }

            @Override
            public void destroy() throws DestroyFailedException {
                recipientKeyPair.getPrivate().destroy();
            }

            @Override
            public boolean isDestroyed() {
                return recipientKeyPair.getPrivate().isDestroyed();
            }
        };
    }
}
