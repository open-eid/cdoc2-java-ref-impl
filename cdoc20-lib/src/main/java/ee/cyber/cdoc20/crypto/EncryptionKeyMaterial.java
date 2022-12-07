package ee.cyber.cdoc20.crypto;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PublicKey;

/**
 * Represents key material required for encryption.
 */
public interface EncryptionKeyMaterial {

    /**
     * @return the key to derive the encryption key
     */
    Key getKey();

    /**
     * @return identifier for the encryption key
     */
    String getLabel();

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel. To decrypt CDOC, recipient must have
     * the private key part of the public key. RSA and EC public keys are supported by CDOC.
     * @param publicKey
     * @param keyLabel
     * @return
     */
    static EncryptionKeyMaterial from(PublicKey publicKey, String keyLabel) {
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return publicKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }
        };
    }

    /**
     * Create EncryptionKeyMaterial from preSharedKey and keyLabel. To decrypt CDOC, recipient must also have same
     * preSharedKey that is identified by the same keyLabel
     * @param preSharedKey preSharedKey will be used to generate key encryption key
     * @param keyLabel unique identifier for preSharedKey
     * @return
     */
    static EncryptionKeyMaterial from(SecretKey preSharedKey, String keyLabel) {
        return new EncryptionKeyMaterial() {

            @Override
            public Key getKey() {
                return preSharedKey;
            }

            @Override
            public String getLabel() {
                return keyLabel;
            }
        };
    }
}
