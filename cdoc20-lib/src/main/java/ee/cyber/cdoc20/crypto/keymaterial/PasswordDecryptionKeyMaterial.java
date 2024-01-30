package ee.cyber.cdoc20.crypto.keymaterial;


/**
 * Represents key material required for decryption with password.
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

    /**
     * @return password chars to derive the key from
     */
    public char[] getPassword() {
        return this.password;
    }

}
