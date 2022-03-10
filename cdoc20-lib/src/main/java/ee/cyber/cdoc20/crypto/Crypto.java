package ee.cyber.cdoc20.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HexFormat;

import at.favre.lib.crypto.HKDF;


import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;


public class Crypto {
    public static final String SECP_384_R_1 = "secp384r1";
    private static Logger log = LoggerFactory.getLogger(Crypto.class);


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
        keyPairGenerator.initialize( new ECGenParameterSpec(SECP_384_R_1));

        //System.out.println("EC provider:" + keyPairGenerator.getProvider());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    public static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey) {
        //BigInteger.toByteArray() returns byte in network byte order
        byte[] xBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineX());
        byte[] yBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineY());

        //EC pubKey in TLS 1.3 format
        //https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        //https://github.com/dushitaoyuan/littleca/blob/5694924eb084e2923bb61550c30c0444ddc68484/littleca-core/src/main/java/com/taoyuanx/ca/core/sm/util/BCECUtil.java#L83
        //https://github.com/bcgit/bc-java/blob/526b5846653100fc521c1a68c02dbe9df3347a29/core/src/main/java/org/bouncycastle/math/ec/ECCurve.java#L410
        byte[] tlsPubKey = new byte[1 + xBytes.length + yBytes.length];
        tlsPubKey[0] = 0x04; //uncompressed

        System.arraycopy(xBytes, 0, tlsPubKey, 1, xBytes.length);
        System.arraycopy(yBytes, 0, tlsPubKey,  1 + xBytes.length, yBytes.length);

        return tlsPubKey;
    }

    /**
     * Decode EcPublicKey from TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param encoded
     * @return
     * @throws InvalidParameterSpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static ECPublicKey decodeEcPublicKeyFromTls(byte[] encoded) throws InvalidParameterSpecException, NoSuchAlgorithmException, InvalidKeySpecException {

        final int expectedLength = 48; //TODO
        if (encoded.length != (2 * expectedLength + 1))
        {
            log.error("Invalid pubKey len {}, expected {}, encoded: {}", encoded.length, expectedLength,
                    HexFormat.of().formatHex(encoded));
            throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
        }

        if (encoded[0] != 0x04) {
            log.error("Illegal EC pub key encoding. Encoded: {}", HexFormat.of().formatHex(encoded));
            throw new IllegalArgumentException("Invalid encoding" );
        }

        BigInteger X = new BigInteger(1, Arrays.copyOfRange(encoded,1, expectedLength+1));
        log.debug("decoded X {}", HexFormat.of().formatHex(X.toByteArray()));
        BigInteger Y = new BigInteger(1, Arrays.copyOfRange(encoded,expectedLength+1, encoded.length));
        log.debug("decoded Y {}", HexFormat.of().formatHex(Y.toByteArray()));

        ECPoint pubPoint = new ECPoint(X, Y);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(SECP_384_R_1));

        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubECSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(pubECSpec);
    }

    private static byte[] toUnsignedByteArray(BigInteger bigInteger) {
        //https://stackoverflow.com/questions/4407779/biginteger-to-byte
        byte[] array = bigInteger.toByteArray();
        int expectedLen = (bigInteger.bitLength() + 7) / 8;
        //log.debug("Crypto::toUnsignedByteArray {}", HexFormat.of().formatHex(array));
        if ((array[0] == 0) && (array.length == expectedLen + 1)) {
            return Arrays.copyOfRange(array, 1, array.length);
        } else {
            if (array.length != expectedLen) {
                log.warn("Expected EC key to be {} bytes, but was {}. bigInteger: {}", expectedLen, array.length, HexFormat.of().formatHex(array));
            }
            return array;
        }
    }

    public static byte[] calcEcDhSharedSecret(ECPrivateKey ecPrivateKey, ECPublicKey otherPublicKey) throws NoSuchAlgorithmException, InvalidKeyException {
        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ecPrivateKey);
        ka.doPhase(otherPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        return sharedSecret;
    }

    public static byte[] deriveKeyEncryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] ecdhSharedSecret = calcEcDhSharedSecret((ECPrivateKey) ecKeyPair.getPrivate(), otherPublicKey);
        byte[] kekPm = HKDF.fromHmacSha256().extract("CDOC20kekpremaster".getBytes(StandardCharsets.UTF_8), ecdhSharedSecret);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes("CDOC20kek".getBytes(StandardCharsets.UTF_8));
        baos.writeBytes(FMKEncryptionMethod.name(FMKEncryptionMethod.XOR).getBytes(StandardCharsets.UTF_8));

        baos.writeBytes(encodeEcPubKeyForTls(otherPublicKey));
        baos.writeBytes(encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));

        return HKDF.fromHmacSha256().expand(kekPm, baos.toByteArray(), keyLen );
    }

    public static byte[] deriveKeyDecryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] ecdhSharedSecret = calcEcDhSharedSecret((ECPrivateKey) ecKeyPair.getPrivate(), otherPublicKey);
        byte[] kekPm = HKDF.fromHmacSha256().extract("CDOC20kekpremaster".getBytes(StandardCharsets.UTF_8), ecdhSharedSecret);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes("CDOC20kek".getBytes(StandardCharsets.UTF_8));
        baos.writeBytes(FMKEncryptionMethod.name(FMKEncryptionMethod.XOR).getBytes(StandardCharsets.UTF_8));

        baos.writeBytes(encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
        baos.writeBytes(encodeEcPubKeyForTls(otherPublicKey));


        return HKDF.fromHmacSha256().expand(kekPm, baos.toByteArray(), keyLen );
    }


    public static byte[] xor(byte[] x1, byte[] x2)
    {
        if (x1.length != x2.length) {
            throw new IllegalArgumentException("Array lengths must be equal "+x1.length+ "!=" +x2.length);
        }
        byte[] out = new byte[x1.length];

        for (int i = x1.length - 1; i >= 0; i--) {
            out[i] = (byte)(x1[i] ^ x2[i]);
        }
        return out;
    }
}
