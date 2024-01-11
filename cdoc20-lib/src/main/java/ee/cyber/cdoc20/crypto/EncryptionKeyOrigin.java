package ee.cyber.cdoc20.crypto;

/**
 * Specifies the source of the encryption key derivation
 */
public enum EncryptionKeyOrigin {
    FROM_SECRET,
    FROM_PASSWORD,
    FROM_PUBLIC_KEY
}
