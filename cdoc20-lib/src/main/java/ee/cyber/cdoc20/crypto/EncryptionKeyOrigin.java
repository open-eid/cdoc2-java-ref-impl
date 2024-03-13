package ee.cyber.cdoc20.crypto;

/**
 * Specifies the source of the encryption key derivation
 */
public enum EncryptionKeyOrigin {
    SECRET,
    PASSWORD,
    PUBLIC_KEY
}
