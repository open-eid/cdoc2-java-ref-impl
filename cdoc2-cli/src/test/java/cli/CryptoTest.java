package cli;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.container.recipients.PBKDF2Recipient;
import ee.cyber.cdoc2.crypto.Crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CryptoTest {

    static final char[] PASSWORD_CHARS = {'m', 'y', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x',
        't', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    @Test
    void testSecretKeyExtractionFromPassword() throws Exception {
        byte[] salt = Crypto.generateSaltForKey();
        byte[] secret1 = Crypto.extractSymmetricKeyFromPassword(
            PASSWORD_CHARS, salt, PBKDF2Recipient.PBKDF2_ITERATIONS
        ).getEncoded();
        byte[] secret2 = Crypto.extractSymmetricKeyFromPassword(
            PASSWORD_CHARS, salt, PBKDF2Recipient.PBKDF2_ITERATIONS
        ).getEncoded();

        assertEquals(Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES, secret1.length);
        assertArrayEquals(secret1, secret2);
    }

}
