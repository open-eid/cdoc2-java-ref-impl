package ee.cyber.cdoc20.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HexFormat;

import at.favre.lib.crypto.HKDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CryptoTest {
    private static Logger log = LoggerFactory.getLogger(CryptoTest.class);

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
        assertTrue(fmk.length == 256/8);

        byte[] cek = Crypto.deriveContentEncryptionKey(fmk);
        assertTrue(cek.length == 256/8);

        byte[] hhk = Crypto.deriveHeaderHmacKey(fmk);
        assertTrue(hhk.length == 256/8);
    }

    @Test
    void testBigInteger() {
        byte[] neg = new BigInteger("-255").toByteArray(); //0xff, 0x01
        byte[] neg254 = new BigInteger("-254").toByteArray(); //0xff, 0x02
        byte[] zero = new BigInteger("0").toByteArray(); // 0x00
        byte[] pos127 = new BigInteger("127").toByteArray(); // 0x7f
        byte[] pos128 = new BigInteger("128").toByteArray(); // 0x00, 0x80
        byte[] pos = new BigInteger("255").toByteArray(); // 0x00, 0xff




        assertEquals(new BigInteger("255"), new BigInteger(1, new byte[] {(byte)0xff}));
        assertEquals(new BigInteger("255"), new BigInteger(1, new byte[] {(byte)0x00, (byte)0xff}));


    }

    @Test
    void testEcPubKeyEncodeDecode() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException {
        log.trace("testEcPubKeyEncodeDecode()");

        KeyPair keyPair = Crypto.generateEcKeyPair();

        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

        byte[] encodedEcPubKey = Crypto.encodeEcPubKeyForTls(ecPublicKey);

        assertEquals(1+48*2, encodedEcPubKey.length);

        ECPublicKey decoded = Crypto.decodeEcPublicKeyFromTls(encodedEcPubKey);

        assertEquals(ecPublicKey.getW(), decoded.getW());
        assertEquals(ecPublicKey, decoded);

        System.out.println();
    }

    @Test
    void testGenSharedSecret() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException {
        KeyPair keyPair = Crypto.generateEcKeyPair();

        KeyPair other = Crypto.generateEcKeyPair();

        byte[] ecdhSharedSecret = Crypto.calcEcDhSharedSecret((ECPrivateKey) keyPair.getPrivate(), (ECPublicKey) other.getPublic());

        assertEquals(48, ecdhSharedSecret.length);
    }

    @Test
    void testXorCrypto() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        log.trace("testXorCrypto()");
        byte[] fmk = Crypto.generateFileMasterKey();
        KeyPair keyPair = Crypto.generateEcKeyPair();
        KeyPair other = Crypto.generateEcKeyPair();

        byte[] kek = Crypto.deriveKeyEncryptionKey(keyPair, (ECPublicKey) other.getPublic(), fmk.length);
        byte[] encryptedFmk = Crypto.xor(fmk, kek);
        byte[] decrypted = Crypto.xor(encryptedFmk, kek);

        log.debug("FMK:       {}", HexFormat.of().formatHex(fmk));
        log.debug("encrypted: {}", HexFormat.of().formatHex(encryptedFmk));
        log.debug("decrypted: {}", HexFormat.of().formatHex(decrypted));

        assertArrayEquals(fmk, decrypted);
    }

    @Test
    void testFmkECCycle() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        log.trace("testFmkECCycle()");
        byte[] fmk = Crypto.generateFileMasterKey();

        KeyPair aliceKeyPair = Crypto.generateEcKeyPair();
        KeyPair bobKeyPair = Crypto.generateEcKeyPair();

        byte[] aliceKek = Crypto.deriveKeyEncryptionKey(aliceKeyPair, (ECPublicKey) bobKeyPair.getPublic(), fmk.length);
        byte[] encryptedFmk = Crypto.xor(fmk, aliceKek);

        byte[] bobKek = Crypto.deriveKeyDecryptionKey(bobKeyPair, (ECPublicKey) aliceKeyPair.getPublic(), fmk.length);
        byte[] decryptedFmk = Crypto.xor(encryptedFmk, bobKek);



        log.debug("FMK:       {}", HexFormat.of().formatHex(fmk));
        log.debug("alice KEK: {}", HexFormat.of().formatHex(aliceKek));
        log.debug("encrypted: {}", HexFormat.of().formatHex(encryptedFmk));
        log.debug("bob KEK:   {}", HexFormat.of().formatHex(bobKek));
        log.debug("decrypted: {}", HexFormat.of().formatHex(decryptedFmk));

        assertArrayEquals(fmk, decryptedFmk);
    }
}
