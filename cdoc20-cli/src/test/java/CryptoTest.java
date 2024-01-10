import org.junit.jupiter.api.Test;

import ee.cyber.cdoc20.crypto.Crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoTest {

    public static final String LABEL = "label_for_salt";
    final static char[] PASSWORD_CHARS = {'m', 'y', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't',
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    @Test
    void testSecretKeyExtractionFromPassword() throws Exception {
        byte[] secret1 = Crypto.deriveKekFromPassword(PASSWORD_CHARS, LABEL).getEncoded();
        byte[] secret2 = Crypto.deriveKekFromPassword(PASSWORD_CHARS, LABEL).getEncoded();

        assertEquals(Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES, secret1.length);
        assertArrayEquals(secret1, secret2);
    }
}
