import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.crypto.Crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoTest {

    static final char[] PASSWORD_CHARS = {'m', 'y', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x',
        't', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    @Test
    void testSecretKeyExtractionFromPassword() throws Exception {
        byte[] salt = Crypto.generateSaltForKey();
        byte[] secret1 = Crypto.extractSymmetricKeyFromPassword(PASSWORD_CHARS, salt).getEncoded();
        byte[] secret2 = Crypto.extractSymmetricKeyFromPassword(PASSWORD_CHARS, salt).getEncoded();

        assertEquals(Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES, secret1.length);
        assertArrayEquals(secret1, secret2);
    }

}
