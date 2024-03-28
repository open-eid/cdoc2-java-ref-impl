package ee.cyber.cdoc2.crypto;

/**
 * Specifies the source of the encryption key derivation
 */
public enum EncryptionKeyOrigin {
    SECRET,
    PASSWORD,
    PUBLIC_KEY
}
