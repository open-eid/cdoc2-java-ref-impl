package ee.cyber.cdoc20.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import at.favre.lib.crypto.HKDF;

public class Crypto {

    /**
     * Content Encryption Key length in octets
     */
    public final static int CEK_LEN_BYTES = 256 / 8;

    /**
     * Header HMAC Key length in octets
     */
    public final static int HHK_LEN_BYTES = 256 / 8; //SHA-256


    public static byte[] generateFileMasterKey() throws NoSuchAlgorithmException {
        byte[] inputKeyingMaterial = new byte[64]; //spec says: ikm should be more than 32bytes of secure random
        SecureRandom.getInstance("NativePRNG").nextBytes(inputKeyingMaterial);
        byte[] fmk = HKDF.fromHmacSha256().extract("CDOC20salt".getBytes(StandardCharsets.UTF_8), inputKeyingMaterial);
        return fmk;
    }

    public static byte[] deriveContentEncryptionKey(byte[] fmk) {
        return HKDF.fromHmacSha256().expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), CEK_LEN_BYTES);
    }

    public static byte[] deriveHeaderHmacKey(byte[] fmk) throws NoSuchAlgorithmException {
        //MessageDigest.getInstance("SHA-256").getDigestLength();
        return HKDF.fromHmacSha256().expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), HHK_LEN_BYTES);
    }

    public static KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");// provider SunEC
        keyPairGenerator.initialize( new ECGenParameterSpec("secp384r1"));

        System.out.println("EC provider:" + keyPairGenerator.getProvider());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    public static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey) {
        //BigInteger.toByteArray() returns byte in network byte order and first byte as sign
        byte[] xBytes = ecPublicKey.getW().getAffineX().toByteArray();
        byte[] yBytes = ecPublicKey.getW().getAffineY().toByteArray();

        //EC pubKey in TLS 1.3 format
        //https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        //https://github.com/dushitaoyuan/littleca/blob/5694924eb084e2923bb61550c30c0444ddc68484/littleca-core/src/main/java/com/taoyuanx/ca/core/sm/util/BCECUtil.java#L83
        //https://github.com/bcgit/bc-java/blob/526b5846653100fc521c1a68c02dbe9df3347a29/core/src/main/java/org/bouncycastle/math/ec/ECCurve.java#L410
        byte[] tlsPubKey = new byte[1 + xBytes.length - 1 + yBytes.length - 1];
        tlsPubKey[0] = 0x04; //uncompressed

        //xyBytes has length is 49bytes, remove first byte devoted for sign
        System.arraycopy(xBytes, 1, tlsPubKey, 1, xBytes.length - 1);
        System.arraycopy(yBytes, 1, tlsPubKey, 1 + xBytes.length - 1, yBytes.length - 1);

        return tlsPubKey;
    }
}
