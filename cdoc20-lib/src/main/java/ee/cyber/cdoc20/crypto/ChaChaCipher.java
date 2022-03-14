package ee.cyber.cdoc20.crypto;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

public class ChaChaCipher {

    private static Logger log = LoggerFactory.getLogger(ChaChaCipher.class);

    public final static int NONCE_LEN_BYTES = 96 / 8;
    public static Cipher initCipher(int mode, Key contentEncryptionKey, byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        if ((nonce == null) || (nonce.length != NONCE_LEN_BYTES)){
            throw new IllegalArgumentException("Invalid nonce");
        }

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");

        //byte[] nonce = Crypto.getSecureRandom().generateSeed(NONCE_LEN_BYTES); //always generate
        // IV, initialization value with nonce
        IvParameterSpec iv = new IvParameterSpec(nonce);

        cipher.init(mode, contentEncryptionKey, iv);
        return cipher;
    }

    public static byte[] encryptPayload(SecretKey cek, byte[] nonce, byte[] src, byte[] additionalData)
            throws InvalidAlgorithmParameterException,
            NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        if ((nonce == null) || (nonce.length != NONCE_LEN_BYTES)){
            throw new IllegalArgumentException("Invalid nonce");
        }

        if ((additionalData == null) || (additionalData.length == 0)) {
            throw new IllegalArgumentException("Invalid additionalData");
        }

        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, cek, nonce);
        cipher.updateAAD(additionalData);
        byte[] encrypted = cipher.doFinal(src);

        ByteBuffer bb = ByteBuffer.allocate(NONCE_LEN_BYTES + encrypted.length);
        bb.put(nonce);
        bb.put(encrypted);
        return bb.array();
    }

    public static byte[] decryptPayload(SecretKey cek, byte[] encrypted, byte[] additionalData)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        if ((encrypted == null) || (encrypted.length <= NONCE_LEN_BYTES)) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }

        if ((additionalData == null) || (additionalData.length == 0)) {
            throw new IllegalArgumentException("Invalid additionalData");
        }

        byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_LEN_BYTES);
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, cek, nonce);

        cipher.updateAAD(additionalData);
        byte[] decrypted = cipher.doFinal(encrypted, NONCE_LEN_BYTES, encrypted.length - NONCE_LEN_BYTES);
        return decrypted;
    }

    public static byte[] getAdditionalData(byte[] header, byte[] headerHMAC) {
        final byte[] cDoc20Payload = "CDOC20payload".getBytes(StandardCharsets.UTF_8);
        ByteBuffer bb = ByteBuffer.allocate(cDoc20Payload.length + header.length + headerHMAC.length);
        bb.put(cDoc20Payload);
        bb.put(header);
        bb.put(headerHMAC);
        return bb.array();
    }

    public static byte[] generateNonce() throws NoSuchAlgorithmException {
        byte[] nonce = new byte[NONCE_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static CipherOutputStream initChaChaOutputStream(OutputStream os,
                                                            SecretKey contentEncryptionKey,
                                                            byte[] nonce,
                                                            byte[] additionalData)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException,
                    NoSuchAlgorithmException, InvalidKeyException, IOException {

        if ((nonce == null) || (nonce.length != NONCE_LEN_BYTES)){
            throw new IllegalArgumentException("Invalid nonce");
        }

        if ((additionalData == null) || (additionalData.length == 0)) {
            throw new IllegalArgumentException("Invalid additionalData");
        }

        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, contentEncryptionKey, nonce);
        cipher.updateAAD(additionalData);
        os.write(nonce);//how to prepend unencrypted nonce
        return new CipherOutputStream(os, cipher);
    }

    public static CipherInputStream initChaChaInputStream(InputStream is,
                                                          SecretKey contentEncryptionKey,
                                                          byte[] additionalData)
            throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException,
                    NoSuchAlgorithmException, InvalidKeyException {

        log.trace("initChaChaInputStream()");
        if ((additionalData == null) || (additionalData.length == 0)) {
            throw new IllegalArgumentException("Invalid additionalData");
        }

        byte[] nonce = is.readNBytes(NONCE_LEN_BYTES);
        //log.debug("nonce hex: {}", HexFormat.of().formatHex(nonce));
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, contentEncryptionKey, nonce);
        cipher.updateAAD(additionalData);
        return new CipherInputStream(is, cipher);
    }

}