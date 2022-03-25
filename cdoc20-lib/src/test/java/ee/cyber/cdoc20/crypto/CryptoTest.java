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

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;


public class CryptoTest {
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
        assertTrue(fmk.length == 256/8);

        //byte[] cek = Crypto.deriveContentEncryptionKey(fmk);
        //assertTrue(cek.length == 256/8);
        SecretKey cekKey = Crypto.deriveContentEncryptionKey(fmk);
        String format = cekKey.getFormat();
        byte[] cekBytes = cekKey.getEncoded();
        assertEquals(Crypto.CEK_LEN_BYTES, cekBytes.length);

        SecretKey hhkKey = Crypto.deriveHeaderHmacKey(fmk);
        byte[] hhkBytes = hhkKey.getEncoded();
        assertTrue( hhkBytes.length == 256/8);
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
        assertEquals(0x04, encodedEcPubKey[0]);

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
    void testFmkECCycle() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        log.trace("testFmkECCycle()");
        byte[] fmk = Crypto.generateFileMasterKey();

        //KeyPair aliceKeyPair = Crypto.generateEcKeyPair();
        KeyPair aliceKeyPair = loadECKeyFromPem();
        KeyPair bobKeyPair = Crypto.generateEcKeyPair();

        byte[] bobPkcs8 = bobKeyPair.getPrivate().getEncoded();
        String bobPEM = Base64.getEncoder().encodeToString(bobPkcs8);

        log.debug("bobPEM {}", bobPEM);

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
            IOException, InvalidKeyException {

        log.trace("testChaChaCipherStream()");
        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] nonce = ChaChaCipher.generateNonce();
        byte[] header = new byte[0];
        byte[] headerHMAC = new byte[0];
        byte[] additionalData = ChaChaCipher.getAdditionalData(header, headerHMAC);
        String payload = "secret";

//        log.debug("nonce hex: {}", HexFormat.of().formatHex(nonce));
//        byte[] encryptedBytes = ChaChaCipher.encryptPayload(cek, nonce, payload.getBytes(StandardCharsets.UTF_8), additionalData);
//        log.debug("encryptedBytes hex: {}", HexFormat.of().formatHex(encryptedBytes));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        CipherOutputStream cos = ChaChaCipher.initChaChaOutputStream(bos, cek, nonce, additionalData);
        cos.write(payload.getBytes(StandardCharsets.UTF_8));
        cos.flush(); // without flush, some bytes are not written
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

    //@Test
    KeyPair loadECKeyFromPem() throws NoSuchAlgorithmException, InvalidKeySpecException {
        //openssl ecparam -name secp384r1 -genkey -noout -out key.pem

        //header/footer and whitespace removed
        String keyPem =
            //-----BEGIN EC PRIVATE KEY-----
            "MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd" +
            "4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j" +
            "C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd" +
            "yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=";
            //-----END EC PRIVATE KEY-----

        //openssl ec -in key.pem -pubout -out public.pem
        //matching pub key with header/footer and whitespaces removed
        String pubKeyPem =
            //-----BEGIN PUBLIC KEY-----
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhEZdaw/m5tmqIrhonGPKG0ZHLPo7fJLO" +
            "IwtYw/3/xEPCnRWKyfisJzOkfKyF6g51JyyRYhdzsw6bvE1I1Tr3V4M0C/p+u0Ii" +
            "3cnq0xOn+boyF6FzZGQfDtpF/97wA7gw";
            //-----END PUBLIC KEY-----


        // static header you can put in front
        final byte[] header = HexFormat.of().parseHex("3081bf020100301006072a8648ce3d020106052b810400220481a7");

        //key from the PEM above
        byte[] pem = Base64.getDecoder().decode(keyPem);

        byte[] pkcs8 = new byte[header.length + pem.length];



        System.arraycopy(header, 0, pkcs8, 0, header.length);
        System.arraycopy(pem, 0,pkcs8, header.length, pem.length);

        PrivateKey ecPrivate = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

        String alg = ecPrivate.getAlgorithm();

        log.debug("{}", HexFormat.of().formatHex(ecPrivate.getEncoded()));

        assertEquals("EC", alg);



        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKeyPem));

        ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(x509EncodedKeySpec);

        assertEquals("EC", ecPublicKey.getAlgorithm());

        byte[] rawPubKey = Crypto.encodeEcPubKeyForTls(ecPublicKey);
        log.debug("{}", HexFormat.of().formatHex(rawPubKey));

        KeyPair keyPair = new KeyPair(ecPublicKey, ecPrivate);
        return keyPair;
    }

    @Test
    void testLoadEcPubKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        //openssl ec -in key.pem -pubout -out public.pem
        String pubKeyPem = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhEZdaw/m5tmqIrhonGPKG0ZHLPo7fJLO" +
                "IwtYw/3/xEPCnRWKyfisJzOkfKyF6g51JyyRYhdzsw6bvE1I1Tr3V4M0C/p+u0Ii" +
                "3cnq0xOn+boyF6FzZGQfDtpF/97wA7gw";

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKeyPem));

        ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(x509EncodedKeySpec);

        assertEquals("EC", ecPublicKey.getAlgorithm());

        byte[] rawPubKey = Crypto.encodeEcPubKeyForTls(ecPublicKey);
        log.debug("{}", HexFormat.of().formatHex(rawPubKey));


    }
}
