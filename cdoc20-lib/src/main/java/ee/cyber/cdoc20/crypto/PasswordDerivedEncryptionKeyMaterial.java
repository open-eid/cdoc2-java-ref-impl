package ee.cyber.cdoc20.crypto;


import java.security.Key;
import javax.crypto.SecretKey;


/**
 * Represents key material required for encryption with password.
 */
public class PasswordDerivedEncryptionKeyMaterial implements EncryptionKeyMaterial {

    private final Key preSharedKey;
    private final String keyLabel;
    private final byte[] passwordSalt;

    public PasswordDerivedEncryptionKeyMaterial(
        SecretKey preSharedKey,
        String keyLabel,
        byte[] passwordSalt
    ) {
        this.preSharedKey = preSharedKey;
        this.keyLabel = keyLabel;
        this.passwordSalt = passwordSalt;
    }

    @Override
    public Key getKey() {
        return preSharedKey;
    }

    @Override
    public String getLabel() {
        return keyLabel;
    }

    /**
     * @return salt used to derive the key from the password
     */
    public byte[] getPasswordSalt() {
        return this.passwordSalt;
    }

}
