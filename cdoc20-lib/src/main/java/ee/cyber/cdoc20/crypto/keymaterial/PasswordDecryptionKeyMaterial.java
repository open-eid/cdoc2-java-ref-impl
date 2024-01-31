package ee.cyber.cdoc20.crypto.keymaterial;


import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;

/**
 * Represents key material required for decryption with symmetric key derived from password.
 */
public class PasswordDecryptionKeyMaterial implements DecryptionKeyMaterial {

    private final String keyLabel;
    private final char[] password;

    public PasswordDecryptionKeyMaterial(char[] password, String keyLabel) {
        this.keyLabel = keyLabel;
        this.password = password;
    }

    @Override
    public Object getRecipientId() {
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.FROM_PASSWORD;
    }

    /**
     * @return password chars to derive the key from
     */
    public char[] getPassword() {
        return this.password;
    }

}
