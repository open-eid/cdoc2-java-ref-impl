package ee.cyber.cdoc20.crypto;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChaChaChipherTest {
    private static final Logger log = LoggerFactory.getLogger(ChaChaChipherTest.class);

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

}
