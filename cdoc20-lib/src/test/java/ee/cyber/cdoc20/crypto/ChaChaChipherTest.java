package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.container.Tar;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChaChaChipherTest {
    private static final Logger log = LoggerFactory.getLogger(ChaChaChipherTest.class);

    @Test
    void testChaCha() throws GeneralSecurityException {
        log.trace("testChaCha()");

        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] additionalData = ChaChaCipher.getAdditionalData(new byte[0], new byte[0]);
        String payload = "secret";
        byte[] encrypted =
                ChaChaCipher.encryptPayload(cek, payload.getBytes(StandardCharsets.UTF_8), additionalData);

        String decrypted = new String(ChaChaCipher.decryptPayload(cek, encrypted, additionalData),
                StandardCharsets.UTF_8);
        assertEquals(payload, decrypted);
    }

    @Test
    void testChaChaCipherStream()
            throws GeneralSecurityException,
            IOException {

        log.trace("testChaChaCipherStream()");
        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] header = new byte[0];
        byte[] headerHMAC = new byte[0];
        byte[] additionalData = ChaChaCipher.getAdditionalData(header, headerHMAC);
        String payload = "secret";


        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (CipherOutputStream cos = ChaChaCipher.initChaChaOutputStream(bos, cek, additionalData)) {
            cos.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        byte[] encrypted = bos.toByteArray();


        ByteArrayInputStream bis = new ByteArrayInputStream(encrypted);

        CipherInputStream cis = ChaChaCipher.initChaChaInputStream(bis, cek, additionalData);

        byte[] buf = new byte[1024];
        int read = cis.read(buf);
        assertTrue(read > 0);
        String decrypted = new String(buf, 0, read, StandardCharsets.UTF_8);

        assertEquals(payload, decrypted);
    }

    @Test
    void testTarGZipChaChaCipherStream()
            throws GeneralSecurityException, IOException {

        log.trace("testTarGZipChaChaCipherStream()");
        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] header = new byte[0];
        byte[] headerHMAC = new byte[0];
        byte[] additionalData = ChaChaCipher.getAdditionalData(header, headerHMAC);
        String payload = "secret";


        //Path encryptedPath = Path.of(System.getProperty("java.io.tmpdir")).resolve( "encrypted.tar.gz");
        //encrypted.toFile().deleteOnExit();


        ByteBuffer encryptedTarGzBuf;

        String tarEntryName = "payload-" + UUID.randomUUID();
        try (ByteArrayOutputStream encryptedTarGzBos = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = ChaChaCipher.initChaChaOutputStream(
                    encryptedTarGzBos, cek, additionalData)) {

            Tar.archiveData(cipherOutputStream, new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)), tarEntryName);
            encryptedTarGzBuf = ByteBuffer.wrap(encryptedTarGzBos.toByteArray());
        }

        try (CipherInputStream cis = ChaChaCipher.initChaChaInputStream(
                new ByteArrayInputStream(encryptedTarGzBuf.array()), cek, additionalData);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Tar.extractTarEntry(cis, out, tarEntryName);
            assertEquals(payload, out.toString(StandardCharsets.UTF_8));
        }
    }


}
