package ee.cyber.cdoc20.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;


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

        //byte[] cek = Crypto.deriveContentEncryptionKey(fmk);
        //assertTrue(cek.length == 256/8);
        SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);
        String format = cekKey.getFormat();
        byte[] cekBytes = cekKey.getEncoded();
        assertEquals(Crypto.CEK_LEN_BYTES, cekBytes.length);

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

    @Test
    void testChaCha() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        log.trace("testChaCha()");

        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] nonce = ChaChaCipher.generateNonce();
        byte[] additionalData = ChaChaCipher.getAdditionalData(new byte[0], new byte[0]);
        String payload = "secret";
        byte[] encrypted = ChaChaCipher.encryptPayload(cek, nonce, payload.getBytes(StandardCharsets.UTF_8), additionalData);

        //log.debug("encrypted hex: {}", HexFormat.of().formatHex(encrypted));
        //log.debug("encrypted str: {}", new String(encrypted));

        String decrypted = new String(ChaChaCipher.decryptPayload(cek, encrypted, additionalData), StandardCharsets.UTF_8);
        assertEquals(payload, decrypted);
    }

    @Test
    void testChaChaCipherStream()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        log.trace("testChaChaCipherStream()");
        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] nonce = ChaChaCipher.generateNonce();
        byte[] additionalData = ChaChaCipher.getAdditionalData(new byte[0], new byte[0]);
        String payload = "secret";

//        log.debug("nonce hex: {}", HexFormat.of().formatHex(nonce));
//        byte[] encryptedBytes = ChaChaCipher.encryptPayload(cek, nonce, payload.getBytes(StandardCharsets.UTF_8), additionalData);
//        log.debug("encryptedBytes hex: {}", HexFormat.of().formatHex(encryptedBytes));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        CipherOutputStream cos = ChaChaCipher.initChaChaOutputStream(bos, cek, nonce, additionalData);
        cos.write(payload.getBytes(StandardCharsets.UTF_8));
        cos.flush(); // without flush, some bytes are not written and decryption fails
        cos.close();

        byte[] encrypted = bos.toByteArray();
//        log.debug("encrypted hex:      {}", HexFormat.of().formatHex(encrypted));
        ByteArrayInputStream bis = new ByteArrayInputStream(encrypted);

        CipherInputStream cis = ChaChaCipher.initChaChaInputStream(bis, cek, additionalData);

        byte[] buf = new byte[1024];
        int read = cis.read(buf);
        assertTrue(read > 0);
        String decrypted = new String(buf, 0, read, StandardCharsets.UTF_8);

        assertEquals(payload, decrypted);
    }

    @Test
    void testHmacSha256() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = "header".getBytes(StandardCharsets.UTF_8);
        byte[] hmac = Crypto.calcHmacSha256(Crypto.generateFileMasterKey(), data);
        assertNotNull(hmac);
        assertEquals(Crypto.HHK_LEN_BYTES, hmac.length);
    }
}
