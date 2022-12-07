package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;

import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


class CryptoTest {
    private static final Logger log = LoggerFactory.getLogger(CryptoTest.class);

    @BeforeAll
    static void initCrypto() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Test
    void testMaxCrypto() throws NoSuchAlgorithmException {
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        assertTrue(maxKeySize > 256);
    }

    @Test
    void testHKDF() throws NoSuchAlgorithmException {
        byte[] fmk = Crypto.generateFileMasterKey();
        assertEquals(Crypto.FMK_LEN_BYTES, fmk.length);

        SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);
        String format = cekKey.getFormat();
        byte[] cekBytes = cekKey.getEncoded();
        assertEquals(Crypto.CEK_LEN_BYTES, cekBytes.length);

        SecretKey hhkKey = Crypto.deriveHeaderHmacKey(fmk);
        byte[] hhkBytes = hhkKey.getEncoded();
        assertEquals(Crypto.HHK_LEN_BYTES, hhkBytes.length);
    }


    @Test
    void testGenSharedSecret() throws GeneralSecurityException {
        KeyPair keyPair = ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1);
        KeyPair other = ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1);
        byte[] ecdhSharedSecret =
                Crypto.calcEcDhSharedSecret(keyPair.getPrivate(), (ECPublicKey) other.getPublic());

        assertEquals(ECKeys.SECP_384_R_1_LEN_BYTES, ecdhSharedSecret.length);
    }

    @Test
    void testXorCrypto() throws GeneralSecurityException {
        log.trace("testXorCrypto()");
        byte[] fmk = Crypto.generateFileMasterKey();
        KeyPair keyPair = ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1);
        KeyPair other = ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1);

        byte[] kek = Crypto.deriveKeyEncryptionKey(keyPair, (ECPublicKey) other.getPublic(), fmk.length);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        byte[] decrypted = Crypto.xor(encryptedFmk, kek);

        log.debug("FMK:       {}", HexFormat.of().formatHex(fmk));
        log.debug("encrypted: {}", HexFormat.of().formatHex(encryptedFmk));
        log.debug("decrypted: {}", HexFormat.of().formatHex(decrypted));

        assertArrayEquals(fmk, decrypted);
    }

    @Test
    void testFmkECCycle() throws GeneralSecurityException, IOException {
        log.trace("testFmkECCycle()");
        byte[] fmk = Crypto.generateFileMasterKey();

        //openssl ecparam -name secp384r1 -genkey -noout -out key.pem
        @SuppressWarnings("checkstyle:OperatorWrap")
        String pem =
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd\n" +
                "4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j\n" +
                "C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd\n" +
                "yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=\n" +
                "-----END EC PRIVATE KEY-----\n";
        KeyPair aliceKeyPair = PemTools.loadKeyPair(pem);
        KeyPair bobKeyPair = ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1);

        byte[] aliceKek = Crypto.deriveKeyEncryptionKey(aliceKeyPair, (ECPublicKey) bobKeyPair.getPublic(), fmk.length);
        byte[] encryptedFmk = Crypto.xor(fmk, aliceKek);

        byte[] bobKek = Crypto.deriveKeyDecryptionKey(bobKeyPair, (ECPublicKey) aliceKeyPair.getPublic(), fmk.length);
        byte[] decryptedFmk = Crypto.xor(encryptedFmk, bobKek);



        log.debug("FMK:       {}", HexFormat.of().formatHex(fmk));
        log.debug("alice KEK: {}", HexFormat.of().formatHex(aliceKek));
        log.debug("encrypted: {}", HexFormat.of().formatHex(encryptedFmk));
        log.debug("bob KEK:   {}", HexFormat.of().formatHex(bobKek));
        log.debug("decrypted: {}", HexFormat.of().formatHex(decryptedFmk));

        assertArrayEquals(aliceKek, bobKek);
        assertArrayEquals(fmk, decryptedFmk);
    }


    @Test
    void testHmacSha256() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = "header".getBytes(StandardCharsets.UTF_8);
        byte[] hmac = Crypto.calcHmacSha256(Crypto.generateFileMasterKey(), data);
        assertNotNull(hmac);
        assertEquals(Crypto.HHK_LEN_BYTES, hmac.length);
    }


    @Test
    void deriveKeyEncryptionKeyFromSharedSecret() {
        byte[] sharedSecret = new byte[32];
        // sharedSecret should be initialized from SecureRandom, for test repeatability sharedSecret in this test is
        // initialized to 0 bytes

        byte[] salt = new byte[32];
        salt[0] = 's';
        salt[1] = 'a';
        salt[2] = 'l';
        salt[3] = 't';

        SecretKey kekSecretKey = Crypto.deriveKeyEncryptionKey("deriveKeyEncryptionKeyFromSharedSecret",
                new SecretKeySpec(sharedSecret, ""),
                salt,
                FMKEncryptionMethod.name(FMKEncryptionMethod.XOR));

        assertEquals("XOR", kekSecretKey.getAlgorithm());
        assertEquals("RAW", kekSecretKey.getFormat()); // SecretKey created using SecretKeySpec

        byte[] kek = kekSecretKey.getEncoded();
        assertNotNull(kek);
        assertEquals(Crypto.FMK_LEN_BYTES, kek.length);
        assertEquals("962b1d44a6e36e9d117136e972e2da0bff7b35fc29b3d8ec5bde246d2c145984",
                HexFormat.of().formatHex(kek));
    }
}
