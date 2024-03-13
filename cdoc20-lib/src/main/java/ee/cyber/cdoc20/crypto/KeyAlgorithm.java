package ee.cyber.cdoc20.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * {@link PublicKey} or {@link PrivateKey} instance algorithm
 */
public final class KeyAlgorithm {

    private KeyAlgorithm() { }

    public enum Algorithm {
        EC,
        RSA
    }

    public static boolean isEcKeysAlgorithm(String keyAlgorithm) {
        return Algorithm.EC.name().equals(keyAlgorithm);
    }

    public static boolean isRsaKeysAlgorithm(String keyAlgorithm) {
        return Algorithm.RSA.name().equals(keyAlgorithm);
    }

}
