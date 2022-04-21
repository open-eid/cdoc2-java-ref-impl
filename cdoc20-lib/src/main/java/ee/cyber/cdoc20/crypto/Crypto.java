package ee.cyber.cdoc20.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import at.favre.lib.crypto.HKDF;

import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static java.security.DrbgParameters.Capability.PR_AND_RESEED;


public final class Crypto {

    private static final Logger log = LoggerFactory.getLogger(Crypto.class);

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
        return HKDF.fromHmacSha256().extract("CDOC20salt".getBytes(StandardCharsets.UTF_8), inputKeyingMaterial);
    }

    public static SecretKey deriveContentEncryptionKey(byte[] fmk) {
        byte[] cekBytes = HKDF.fromHmacSha256()
                .expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), CEK_LEN_BYTES);
        return new SecretKeySpec(cekBytes, "ChaCha20");
    }

    public static SecretKey deriveHeaderHmacKey(byte[] fmk) {
        byte[] hhk = HKDF.fromHmacSha256().expand(fmk, "CDOC20hmac".getBytes(StandardCharsets.UTF_8), HHK_LEN_BYTES);
        return new SecretKeySpec(hhk, HMAC_SHA_256);
    }

    private static KeyAgreement getKeyAgreement() throws NoSuchAlgorithmException {
        Provider pkcs11Provider = Security.getProvider("SunPKCS11-OpenSC");
        return  ((pkcs11Provider != null) && pkcs11Provider.isConfigured())
                ? KeyAgreement.getInstance("ECDH", pkcs11Provider)
                : KeyAgreement.getInstance("ECDH");

    }

    public static byte[] calcEcDhSharedSecret(PrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws GeneralSecurityException {

        Provider sunPKCS11Provider = Security.getProvider("SunPKCS11-OpenSC");
        KeyAgreement keyAgreement;

        // KeyAgreement instances (software and pkcs11) don't work with other provider private keys
        // As pkcs11 loaded key is not instance of ECPrivateKey, then it's possible to differentiate between keys
        // ECPublicKey are basically all "soft" keys
        if ((sunPKCS11Provider != null) && sunPKCS11Provider.isConfigured() && (!(ecPrivateKey instanceof ECPrivateKey))) {
            keyAgreement = KeyAgreement.getInstance("ECDH", sunPKCS11Provider);
        } else {
            keyAgreement = KeyAgreement.getInstance("ECDH");
        }

        return calcEcDhSharedSecret(keyAgreement, ecPrivateKey, otherPublicKey);
    }

    public static byte[] calcEcDhSharedSecret(KeyAgreement ka, PrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws GeneralSecurityException {

        log.debug("ECDH provider {}", ka.getProvider());
        ka.init(ecPrivateKey);
        ka.doPhase(otherPublicKey, true);

        //shared secret
        return ka.generateSecret();
    }


    public static byte[] deriveKeyEncryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws GeneralSecurityException {

        return deriveKek(ecKeyPair, otherPublicKey, keyLen, true);
    }

//    public static byte[] deriveKeyEncryptionKey(KeyAgreement ka, KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
//            throws GeneralSecurityException {
//
//        return deriveKek(ka, ecKeyPair, otherPublicKey, keyLen, true);
//    }

    public static byte[] deriveKeyDecryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws GeneralSecurityException {
        return deriveKek(ecKeyPair, otherPublicKey, keyLen, false);
    }

//    public static byte[] deriveKeyDecryptionKey(KeyAgreement ka, KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
//            throws GeneralSecurityException {
//        return deriveKek(ka, ecKeyPair, otherPublicKey, keyLen, false);
//    }


    private static byte[] deriveKek(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen, boolean isEncryptionMode)
            throws GeneralSecurityException {

        byte[] ecdhSharedSecret = calcEcDhSharedSecret(ecKeyPair.getPrivate(), otherPublicKey);
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
