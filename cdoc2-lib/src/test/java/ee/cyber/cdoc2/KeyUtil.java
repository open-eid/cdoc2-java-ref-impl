package ee.cyber.cdoc2;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import ee.cyber.cdoc2.crypto.KeyAlgorithm;

public final class KeyUtil {

    private KeyUtil() { }

    public static KeyPairGenerator getKeyPairRsaInstance() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(KeyAlgorithm.Algorithm.RSA.name());
    }

}
