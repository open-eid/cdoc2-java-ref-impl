package ee.cyber.cdoc20.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import at.favre.lib.crypto.HKDF;

import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static java.security.DrbgParameters.Capability.PR_AND_RESEED;


public final class Crypto {

    /**
     * Key length for secp384r1 curve
     */
    public static final int SECP_384_R_1_LEN_BYTES = 384 / 8;

    /**
     * File Master Key length in octets
     */
    public static final  int FMK_LEN_BYTES = 256 / 8;

    /**
     * Content Encryption Key length in octets
     */
    public static final  int CEK_LEN_BYTES = 256 / 8;

    /**
     * Header HMAC Key length in octets
     */
    public static final  int HHK_LEN_BYTES = 256 / 8; //SHA-256

    public static final String HMAC_SHA_256 = "HmacSHA256";

    private Crypto() {
    }

    public static SecureRandom getSecureRandom() throws NoSuchAlgorithmException {
        //https://www.veracode.com/blog/research/java-crypto-catchup
        return SecureRandom.getInstance("DRBG", //NIST SP 800-90Ar1
                DrbgParameters.instantiation(256,  // Required security strength
                        PR_AND_RESEED,  // configure algorithm to provide prediction resistance and reseeding facilities
                        "CDOC20".getBytes() // personalization string, used to derive seed
                )
        );
    }

    public static byte[] generateFileMasterKey() throws NoSuchAlgorithmException {
        byte[] inputKeyingMaterial = new byte[64]; //spec says: ikm should be more than 32bytes of secure random
        getSecureRandom().nextBytes(inputKeyingMaterial);
        byte[] fmk = HKDF.fromHmacSha256().extract("CDOC20salt".getBytes(StandardCharsets.UTF_8), inputKeyingMaterial);
        return fmk;
    }

    public static SecretKey deriveContentEncryptionKey(byte[] fmk) {
        byte[] cekBytes = HKDF.fromHmacSha256()
                .expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), CEK_LEN_BYTES);
        SecretKeySpec secretKeySpec = new SecretKeySpec(cekBytes, "ChaCha20");
        return secretKeySpec;
    }

    public static SecretKey deriveHeaderHmacKey(byte[] fmk) {
        byte[] hhk = HKDF.fromHmacSha256().expand(fmk, "CDOC20hmac".getBytes(StandardCharsets.UTF_8), HHK_LEN_BYTES);
        return new SecretKeySpec(hhk, HMAC_SHA_256);
    }


    public static byte[] calcEcDhSharedSecret(ECPrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws NoSuchAlgorithmException, InvalidKeyException {

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ecPrivateKey);
        ka.doPhase(otherPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        return sharedSecret;
    }

    public static byte[] deriveKeyEncryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws NoSuchAlgorithmException, InvalidKeyException {

        return deriveKek(ecKeyPair, otherPublicKey, keyLen, true);
    }

    public static byte[] deriveKeyDecryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws NoSuchAlgorithmException, InvalidKeyException {
        return deriveKek(ecKeyPair, otherPublicKey, keyLen, false);
    }

    private static byte[] deriveKek(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen, boolean isEncryptionMode)
            throws NoSuchAlgorithmException, InvalidKeyException {

        byte[] ecdhSharedSecret = calcEcDhSharedSecret((ECPrivateKey) ecKeyPair.getPrivate(), otherPublicKey);
        byte[] kekPm = HKDF.fromHmacSha256()
                .extract("CDOC20kekpremaster".getBytes(StandardCharsets.UTF_8), ecdhSharedSecret);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes("CDOC20kek".getBytes(StandardCharsets.UTF_8));
        baos.writeBytes(FMKEncryptionMethod.name(FMKEncryptionMethod.XOR).getBytes(StandardCharsets.UTF_8));

        if (isEncryptionMode) {
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls(otherPublicKey));
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
        } else {
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls(otherPublicKey));
        }

        return HKDF.fromHmacSha256().expand(kekPm, baos.toByteArray(), keyLen);
    }

    public static byte[] calcHmacSha256(byte[] fmk, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(deriveHeaderHmacKey(fmk));
        return mac.doFinal(data);
    }

    public static byte[] calcHmacSha256(SecretKey hhk, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(hhk);
        return mac.doFinal(data);
    }




    public static byte[] xor(byte[] x1, byte[] x2) {

        if ((x1 == null) || (x2 == null)) {
            throw new IllegalArgumentException("Cannot xor null value");
        }
        if (x1.length != x2.length) {
            throw new IllegalArgumentException("Array lengths must be equal " + x1.length + "!=" + x2.length);
        }

        byte[] out = new byte[x1.length];
        for (int i = x1.length - 1; i >= 0; i--) {
            out[i] = (byte)(x1[i] ^ x2[i]);
        }
        return out;
    }

}
