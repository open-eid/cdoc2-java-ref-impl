package ee.cyber.cdoc20.crypto;

/**
 * Specifies the source of the encryption key derivation
 */
public enum EncryptionKeyOrigin {
    FROM_SECRET("secret"),
    FROM_PASSWORD("password"),
    FROM_PUBLIC_KEY("public key");

    private final String keyName;

    EncryptionKeyOrigin(String keyName) {
        this.keyName = keyName;
    }

    public String getKeyName() {
        return this.keyName;
    }
}
