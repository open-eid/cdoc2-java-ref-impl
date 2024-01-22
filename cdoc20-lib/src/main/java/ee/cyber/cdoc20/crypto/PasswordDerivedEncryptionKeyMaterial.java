package ee.cyber.cdoc20.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

public interface PasswordDerivedEncryptionKeyMaterial extends EncryptionKeyMaterial {

    /**
     * @return salt used to derive the key from the password
     */
    byte[] getPasswordSalt();

    /**
     * Create PasswordDerivedEncryptionKeyMaterial from password.
     * To decrypt CDOC, recipient must also have same preSharedKey and salt that are identified by
     * the same keyLabel
     * @param password password chars for extracting pre-shared SecretKey
     * @param keyLabel unique identifier for preSharedKey
     * @return PasswordDerivedEncryptionKeyMaterial object
     */
    static PasswordDerivedEncryptionKeyMaterial fromPassword(
        char[] password, String keyLabel
    ) throws GeneralSecurityException {
        byte[] passwordSalt = Crypto.generateSaltForKey();
        SecretKey preSharedKey = Crypto.extractKeyMaterialFromPassword(password, passwordSalt);

        return new PasswordDerivedEncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return preSharedKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }

            @Override
            public byte[] getPasswordSalt() {
                return passwordSalt;
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

}
