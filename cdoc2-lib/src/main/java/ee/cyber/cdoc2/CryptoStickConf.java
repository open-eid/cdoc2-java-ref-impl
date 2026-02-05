package ee.cyber.cdoc2;

/**
 * Enum holding information about the crypto stick used for decryption
 */
public enum CryptoStickConf {
    SECP256R1(256),
    SECP384R1(384),
    RSA3072(3072),
    RSA4096(4096);

    private final int keySize;

    CryptoStickConf(int keySize) {
        this.keySize = keySize;
    }

    public int getKeySizeInBytes() {
        return keySize / 8;
    }
}
