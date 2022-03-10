package ee.cyber.cdoc20.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import at.favre.lib.crypto.HKDF;



public class CryptoTest {

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
    void testEccKeyGen() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        //KeyFactory kf = KeyFactory.getInstance("EC");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");// provider SunEC
        keyPairGenerator.initialize( new ECGenParameterSpec("secp384r1"));

        System.out.println("EC provider:" + keyPairGenerator.getProvider());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        //s key
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        String format = privateKey.getFormat();
        System.out.println("privKey format:"+format);
        System.out.println("pubKey format:"+pubKey.getFormat());
        byte[] privKeyPkcs8 = privateKey.getEncoded();
        byte[] pubKeyX509 = pubKey.getEncoded();


        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECPublicKey ecPublicKey = (ECPublicKey) pubKey;

        //network byte order with first byte as sign
        byte[] xBytes = ecPublicKey.getW().getAffineX().toByteArray();
        byte[] yBytes = ecPublicKey.getW().getAffineY().toByteArray();


        //EC pubKey in TLS 1.3 format
        //https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        //https://github.com/dushitaoyuan/littleca/blob/5694924eb084e2923bb61550c30c0444ddc68484/littleca-core/src/main/java/com/taoyuanx/ca/core/sm/util/BCECUtil.java#L83
        //https://github.com/bcgit/bc-java/blob/526b5846653100fc521c1a68c02dbe9df3347a29/core/src/main/java/org/bouncycastle/math/ec/ECCurve.java#L410
        byte[] tlsPubKey = new byte[1 + xBytes.length + yBytes.length];
        tlsPubKey[0] = 0x04;

        //FIXME: xyBytes has length is 49bytes, so first byte is sign and must be removed? Also byte order in array?
        System.arraycopy(xBytes, 0, tlsPubKey, 1, xBytes.length);
        System.arraycopy(yBytes, 0, tlsPubKey, 1 + xBytes.length, yBytes.length);




        //byte[] encodedPubKey = new byte[1 + xBytes.length + yBytes.length];
//        byte[] sitt = new byte[1];
//        encodedPubKey[0] = 0x04;


        // 49 bytes starting with 0, first byte is sign
        //byte[] privKeyRaw = ecPrivateKey.getS().toByteArray();
//        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(privKeyOctets);
//        pkcs8.


        System.out.println();
    }
}
