import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc20.crypto.Crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoTest {

    public static final String LABEL = "label_for_salt";
    static final char[] PASSWORD_CHARS = {'m', 'y', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x',
        't', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    @Test
    void testSecretKeyExtractionFromPassword() throws Exception {
        // ToDo replace salt via Crypto.generateSaltForKey() after extracting it for decryption flow
        byte[] salt = LABEL.getBytes(StandardCharsets.UTF_8);
        byte[] secret1 = Crypto.deriveKekFromPassword(PASSWORD_CHARS, salt).getEncoded();
        byte[] secret2 = Crypto.deriveKekFromPassword(PASSWORD_CHARS, salt).getEncoded();

        assertEquals(Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES, secret1.length);
        assertArrayEquals(secret1, secret2);
    }
}
