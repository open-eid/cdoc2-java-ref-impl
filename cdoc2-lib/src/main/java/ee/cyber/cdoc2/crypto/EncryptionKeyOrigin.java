package ee.cyber.cdoc2.crypto;


/**
 * Specifies the source of the encryption key derivation
 */
public enum EncryptionKeyOrigin {
    CERTIFICATE,
    ID_CARD,
    KEY_SHARE,
    PASSWORD,
    PUBLIC_KEY,
    SECRET
}
