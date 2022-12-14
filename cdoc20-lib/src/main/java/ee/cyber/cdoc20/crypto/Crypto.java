package ee.cyber.cdoc20.crypto;

import at.favre.lib.crypto.HKDF;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

public final class Crypto {
    private static final Logger log = LoggerFactory.getLogger(Crypto.class);

    /**
     * SecureRandom instance not to "run out of entropy"
     */
    private static SecureRandom secureRandomInstance = null;

    /**
     * File Master Key length in octets
     */
    public static final int FMK_LEN_BYTES = 256 / 8;


    /**
     * Kek is used to encrypt FMK. For XOR length must match FMK
     */
    public static final int KEK_LEN_BYTES = FMK_LEN_BYTES;

    /**
     * Content Encryption Key length in octets
     */
    public static final int CEK_LEN_BYTES = 256 / 8;

    /**
     * Header HMAC Key length in octets
     */
    public static final int HHK_LEN_BYTES = 256 / 8; //SHA-256

    public static final String HMAC_SHA_256 = "HmacSHA256";

    public static final int SYMMETRIC_KEY_MIN_LEN_BYTES = 256 / 8;



    private Crypto() {
    }


    /**
     * Get SecureRandom instance
     * @return SecureRandom
     * @throws NoSuchAlgorithmException if SecureRandom initialization failed
     */
    public static synchronized SecureRandom getSecureRandom() throws NoSuchAlgorithmException {
        if (secureRandomInstance == null) {
            secureRandomInstance = createSecureRandom();
        }
        return secureRandomInstance;
    }

    /**
     * Create SecureRandom
     * @throws NoSuchAlgorithmException if SecureRandom initialization failed
     */
    private static SecureRandom createSecureRandom() throws NoSuchAlgorithmException {
        log.debug("Initializing SecureRandom");

        //https://www.veracode.com/blog/research/java-crypto-catchup
        SecureRandom sRnd = SecureRandom.getInstance("DRBG", //NIST SP 800-90Ar1
            DrbgParameters.instantiation(
                256, // Required security strength
                PR_AND_RESEED, // configure algorithm to provide prediction resistance and reseeding facilities
                "CDOC20".getBytes() // personalization string, used to derive seed
            )
        );
        log.info("Initialized SecureRandom.");
        return sRnd;
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

    /**
     * Derive KEK from salt and secret. Used in symmetric key scenario only.
     * @param label Label identifying pre shared secret
     * @param preSharedSecretKey pre shared secret between parties (sender and recipient) used to derive KEK.
     *                           Min len of 32 bytes
     * @param salt salt minimum length of 32 bytes
     * @param fmkEncMethod fmk encryption method from {@link FMKEncryptionMethod#names}.
     *                     Currently, only "XOR" is valid value
     * @return
     */
    public static SecretKey deriveKeyEncryptionKey(String label, SecretKey preSharedSecretKey, byte[] salt,
                                                   String fmkEncMethod) {

        final int minSaltLen = 256 / 8;
        Objects.requireNonNull(label);
        Objects.requireNonNull(preSharedSecretKey);
        Objects.requireNonNull(preSharedSecretKey.getEncoded());
        Objects.requireNonNull(salt);
        Objects.requireNonNull(fmkEncMethod);

        if (preSharedSecretKey.getEncoded().length < SYMMETRIC_KEY_MIN_LEN_BYTES) {
            throw new IllegalArgumentException("preSharedSecretKey must be at least "
                    + SYMMETRIC_KEY_MIN_LEN_BYTES + " bytes");
        }

        if (salt.length < minSaltLen) {
            throw new IllegalArgumentException("Salt must be at least " + minSaltLen + " bytes");
        }

        // Currently, only XOR is supported
        if (!FMKEncryptionMethod.name(FMKEncryptionMethod.XOR).equalsIgnoreCase(fmkEncMethod)) {
            throw new IllegalArgumentException("Unknown FMK encryption method " + fmkEncMethod);
        }

        final HKDF hkdf = HKDF.fromHmacSha256();
        byte[] kekPm = hkdf.extract(salt, preSharedSecretKey.getEncoded());

        String info = "CDOC20kek" + fmkEncMethod + label;
        byte[] kek = hkdf.expand(kekPm, info.getBytes(StandardCharsets.UTF_8), FMK_LEN_BYTES);

        return new SecretKeySpec(kek, FMKEncryptionMethod.name(FMKEncryptionMethod.XOR));
    }


    public static byte[] calcEcDhSharedSecret(PrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws GeneralSecurityException {

        KeyAgreement keyAgreement;

        // KeyAgreement instances (software and pkcs11) don't work with other provider private keys
        // As pkcs11 loaded key is not instance of ECPrivateKey, then it's possible to differentiate between keys
        // ECPublicKey is always "soft" key
        if (isECPKCS11Key(ecPrivateKey) && (Pkcs11Tools.getConfiguredPKCS11Provider() != null)) {
            keyAgreement = KeyAgreement.getInstance("ECDH", Pkcs11Tools.getConfiguredPKCS11Provider());
        } else {
            keyAgreement = KeyAgreement.getInstance("ECDH");
        }

        return calcEcDhSharedSecret(keyAgreement, ecPrivateKey, otherPublicKey);
    }

    /**
     * If key is EC PKCS11 key (unextractable hardware key), that should only be used by the provider associated with
     * that token
     * @param key checked
     * @return true if key is EC key from PKCS11 or other hardware provider. Note that !isECPKCS11Key doesn't mean that
     *      the key is EC software key as key might be for some other algorithm
     */
    @SuppressWarnings("checkstyle:LineLength")
    public static boolean isECPKCS11Key(PrivateKey key) {
        // might be manufacturer specif, this true for Manufacturer ID: AS Sertifitseerimiskeskus
        // accessed through opensc-pkcs11
        // .toString(): "SunPKCS11-OpenSC EC private key, 384 bitstoken object, sensitive, unextractable)"
        // .getClass(): sun.security.pkcs11.P11Key$P11PrivateKey

        // https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-508B5E3B-BF39-4E02-A1BD-523352D3AA12
        // Software Key objects (or any Key object that has access to the actual key material) should implement
        // the interfaces in the java.security.interfaces and javax.crypto.interfaces packages (such as DSAPrivateKey).
        //
        // Key objects representing unextractable token keys should only implement the relevant generic interfaces in
        // the java.security and javax.crypto packages (PrivateKey, PublicKey, or SecretKey). Identification of
        // the algorithm of a key should be performed using the Key.getAlgorithm() method.
        // Note that a Key object for an unextractable token key can only be used by the provider associated with that
        // token.

        // algorithm is EC, but doesn't implement java.security.interfaces.ECKey
        return ("EC".equals(key.getAlgorithm()) && !(key instanceof java.security.interfaces.ECKey));
    }

    public static byte[] calcEcDhSharedSecret(KeyAgreement ka, PrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws GeneralSecurityException {

        //log.debug("ECDH provider {}", ka.getProvider());
        ka.init(ecPrivateKey);
        ka.doPhase(otherPublicKey, true);

        //shared secret
        return ka.generateSecret();
    }

    public static byte[] deriveKeyEncryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws GeneralSecurityException {

        return deriveKek(ecKeyPair, otherPublicKey, keyLen, true);
    }

    public static byte[] deriveKeyDecryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws GeneralSecurityException {
        return deriveKek(ecKeyPair, otherPublicKey, keyLen, false);
    }

    /**
     * Derive KEK for EC scenarios
     * @param ecKeyPair
     * @param otherPublicKey
     * @param keyLen
     * @param isEncryptionMode
     * @return
     * @throws GeneralSecurityException
     */
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

    /**
     * Calculate HMAC
     * @param hhk HMAC header key. For CDOC2 {@link Crypto#deriveHeaderHmacKey(byte[])}
     * @param data input – data in bytes. For CDOC2 this is header FlatBuffers bytes
     * @return the MAC result.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] calcHmacSha256(SecretKey hhk, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(hhk);
        return mac.doFinal(data);
    }

    /**
     * XOR two byte arrays
     * @param x1 byte array
     * @param x2 byte array
     * @return xor result
     */
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
