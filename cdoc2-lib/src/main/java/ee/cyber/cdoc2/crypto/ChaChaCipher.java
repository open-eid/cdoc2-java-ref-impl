package ee.cyber.cdoc2.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

import ee.cyber.cdoc2.container.Envelope;

public final class ChaChaCipher {

    private static final Logger log = LoggerFactory.getLogger(ChaChaCipher.class);
    public static final int NONCE_LEN_BYTES = 96 / 8;

    //Sun ChaChaCipher decryption fails with big files, use BouncyCastle implementation for ChaCha
    static final Provider BC = new BouncyCastleProvider();

    private static final String INVALID_ADDITIONAL_DATA = "Invalid Additional Authentication Data (AAD)";

    private ChaChaCipher() {
    }

    /**
     * Init ChaCha20-Poly1305 Cipher with contentEncryptionKey and nonce
     * @param mode {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
     * @param contentEncryptionKey CEK, {@link Crypto#deriveContentEncryptionKey(byte[])}
     * @param nonce if ENCRYPT mode then {@link #NONCE_LEN_BYTES } bytes of secure random, otherwise nonce read from
     *              InputStream
     * @return an initialized Cipher
     * @throws GeneralSecurityException
     */
    private static Cipher initCipher(int mode, Key contentEncryptionKey, byte[] nonce)
            throws GeneralSecurityException {

        if ((nonce == null) || (nonce.length != NONCE_LEN_BYTES)) {
            throw new IllegalArgumentException("Invalid nonce");
        }

        // Triggers S5542 Security vulnerability, but S5542 check only knows about AES and RSA and all other algorithms
        // without method and padding are incorrectly marked as insecure (ChaCha20 stream cipher does not have a
        // block operation mode and do not use padding and therefor cannot be specified):
        // https://github.com/SonarSource/sonar-java/blob/master/java-checks/src/
        //                main/java/org/sonar/java/checks/security/EncryptionAlgorithmCheck.java
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", BC); //NOSONAR - S5542


        // IV, initialization value with nonce
        // Triggers S3329 - Use a dynamically-generated, random IV.
        // SQ fails to detect that nonce *is* generated from secure random
        IvParameterSpec iv = new IvParameterSpec(nonce); //NOSONAR - S3329
        cipher.init(mode, contentEncryptionKey, iv);
        return cipher;
    }

    /**
     *
     * @param cek content encryption key CEK, {@link Crypto#deriveContentEncryptionKey(byte[])}
     * @param src payload to encrypt
     * @param aad Additional Authentication Data (AAD) provided to ChaChaCipher
     *        {@link Envelope#getAdditionalData(byte[], byte[])}
     * @return src encrypted with cek. First 12 bytes are nonce, rest is encrypted payload
     * @throws GeneralSecurityException
     */
    public static byte[] encryptPayload(SecretKey cek, byte[] src, byte[] aad)
            throws GeneralSecurityException {

        if ((aad == null) || (aad.length == 0)) {
            throw new IllegalArgumentException(INVALID_ADDITIONAL_DATA);
        }

        byte[] nonce = generateNonce();
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, cek, nonce);
        cipher.updateAAD(aad);
        byte[] encrypted = cipher.doFinal(src);

        ByteBuffer bb = ByteBuffer.allocate(NONCE_LEN_BYTES + encrypted.length);
        bb.put(nonce);
        bb.put(encrypted);
        return bb.array();
    }

    /**
     *
     * @param cek content encryption key CEK, {@link Crypto#deriveContentEncryptionKey(byte[])}
     * @param encrypted encrypted payload. First 12 bytes of encrypted is nonce.
     * @param aad Additional Authentication Data (AAD) provided to ChaChaCipher
     *        {@link Envelope#getAdditionalData(byte[], byte[])}
     * @return decrypted payload.
     * @throws GeneralSecurityException if decryption has failed
     */
    public static byte[] decryptPayload(SecretKey cek, byte[] encrypted, byte[] aad)
            throws GeneralSecurityException {

        if ((encrypted == null) || (encrypted.length <= NONCE_LEN_BYTES)) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }

        if ((aad == null) || (aad.length == 0)) {
            throw new IllegalArgumentException(INVALID_ADDITIONAL_DATA);
        }

        byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_LEN_BYTES);
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, cek, nonce);
        cipher.updateAAD(aad);
        return cipher.doFinal(encrypted, NONCE_LEN_BYTES, encrypted.length - NONCE_LEN_BYTES);
    }

    private static byte[] generateNonce() throws NoSuchAlgorithmException {
        byte[] nonce = new byte[NONCE_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Constructs a CipherOutputStream from an OutputStream and ChaChaCipher
     * @param os the OutputStream object
     * @param contentEncryptionKey  cek content encryption key CEK, {@link Crypto#deriveContentEncryptionKey(byte[])}
     * @param additionalData Additional Authentication Data (AAD) provided to ChaChaCipher
     *        {@link Envelope#getAdditionalData(byte[], byte[])}
     * @return CipherOutputStream
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static CipherOutputStream initChaChaOutputStream(OutputStream os,
                                                            SecretKey contentEncryptionKey,
                                                            byte[] additionalData)
            throws GeneralSecurityException, IOException {

        if ((additionalData == null) || (additionalData.length == 0)) {
            throw new IllegalArgumentException(INVALID_ADDITIONAL_DATA);
        }

        byte[] nonce = generateNonce();
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, contentEncryptionKey, nonce);
        cipher.updateAAD(additionalData);
        os.write(nonce); //prepend plaintext nonce
        return new CipherOutputStream(os, cipher);
    }

    /**
     * Constructs a CipherInputStream from an InputStream and a ChaChaCipher.
     * @param is the to-be-processed input stream
     * @param contentEncryptionKey contentEncryptionKey  cek content encryption key CEK,
     *          {@link Crypto#deriveContentEncryptionKey(byte[])}
     * @param additionalData Additional Authentication Data (AAD) provided to ChaChaCipher
     *        {@link Envelope#getAdditionalData(byte[], byte[])}
     * @return CipherInputStream
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static CipherInputStream initChaChaInputStream(InputStream is,
                                                          SecretKey contentEncryptionKey,
                                                          byte[] additionalData)
            throws IOException, GeneralSecurityException {

        log.trace("initChaChaInputStream()");
        if ((additionalData == null) || (additionalData.length == 0)) {
            throw new IllegalArgumentException(INVALID_ADDITIONAL_DATA);
        }

        byte[] nonce = is.readNBytes(NONCE_LEN_BYTES);
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, contentEncryptionKey, nonce);
        cipher.updateAAD(additionalData);
        return new CipherInputStream(is, cipher);
    }

}
