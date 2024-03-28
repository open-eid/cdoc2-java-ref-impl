package ee.cyber.cdoc2.crypto;

import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.container.Tar;
import ee.cyber.cdoc2.container.TarDeflate;

import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateParameters;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChaChaChipherTest {
    private static final Logger log = LoggerFactory.getLogger(ChaChaChipherTest.class);

    @Test
    void testChaCha() throws GeneralSecurityException {
        log.trace("testChaCha()");

        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());

        byte[] additionalData = Envelope.getAdditionalData(new byte[0], new byte[0]);
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
        byte[] additionalData = Envelope.getAdditionalData(header, headerHMAC);
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
        byte[] additionalData = Envelope.getAdditionalData(header, headerHMAC);
        String payload = "secret";


        //Path encryptedPath = Path.of(System.getProperty("java.io.tmpdir")).resolve( "encrypted.tar.gz");
        //encrypted.toFile().deleteOnExit();


        ByteBuffer encryptedTarGzBuf;

        String tarEntryName = "payload-" + UUID.randomUUID();
        try (ByteArrayOutputStream encryptedTarGzBos = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = ChaChaCipher.initChaChaOutputStream(
                    encryptedTarGzBos, cek, additionalData)) {

            Tar.archiveData(cipherOutputStream, new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)),
                    tarEntryName);
            encryptedTarGzBuf = ByteBuffer.wrap(encryptedTarGzBos.toByteArray());
        }

        try (CipherInputStream cis = ChaChaCipher.initChaChaInputStream(
                new ByteArrayInputStream(encryptedTarGzBuf.array()), cek, additionalData);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Tar.extractTarEntry(cis, out, tarEntryName);
            assertEquals(payload, out.toString(StandardCharsets.UTF_8));
        }
    }

    @Test
    void findTarZChaChaCipherStreamMin() throws IOException, GeneralSecurityException {
        //see also TarGzTest.findZlibMinSize


        //Create empty.tar and compress it with deflate
        ByteArrayOutputStream destEmptyTarZ = new ByteArrayOutputStream();
        // https://superuser.com/questions/448623/how-to-get-an-empty-tar-archive
        byte[] emptyTarBytes = new byte[1024]; //1024 bytes of 0x00 is valid tar archive, see link above
        InputStream emptyTar = new ByteArrayInputStream(emptyTarBytes);
        DeflateParameters deflateParameters = new DeflateParameters();
        deflateParameters.setCompressionLevel(9);
        try (DeflateCompressorOutputStream zOs =
                     new DeflateCompressorOutputStream(new BufferedOutputStream(destEmptyTarZ), deflateParameters)) {
            emptyTar.transferTo(zOs);
        }

        log.debug("Compressed empty.tar {}", destEmptyTarZ.size()); //17
        // Tar is able to process empty tar without exceptions
        Assertions.assertTrue(TarDeflate.listFiles(new ByteArrayInputStream(destEmptyTarZ.toByteArray())).isEmpty());

        // encrypt compressed empty.tar with ChaCha stream, find out size
        SecretKey cek = Crypto.deriveContentEncryptionKey(Crypto.generateFileMasterKey());
        byte[] header = new byte[0];
        byte[] headerHMAC = new byte[0];
        byte[] additionalData = Envelope.getAdditionalData(header, headerHMAC);

        ByteArrayInputStream minCompressedTarInputStream = new ByteArrayInputStream(destEmptyTarZ.toByteArray());
        ByteArrayOutputStream encryptedTarGzBos = new ByteArrayOutputStream();

        try (CipherOutputStream cipherOutputStream = ChaChaCipher.initChaChaOutputStream(
                     encryptedTarGzBos, cek, additionalData)) {

            minCompressedTarInputStream.transferTo(cipherOutputStream);
        }

        log.debug("ChaCha encrypted minimum compressed tar {} bytes", encryptedTarGzBos.size());
        //nonce 12 + min compressed tar 17 + Poly1305 MAC 16
        //45 - value for Envelope.MIN_PAYLOAD_LEN
        assertTrue(encryptedTarGzBos.size() >= Envelope.MIN_PAYLOAD_LEN);
    }

    @Test // test speed of ChaCha cipher - on SSD decrypting 8GB took ~105 seconds (just reading file 17 seconds)
    @Tag("slow")
    void testChaChaCipherSpeed(@TempDir Path tempDir) throws IOException, GeneralSecurityException {
        String bigFileName = "bigFile";
        String bigFileNameEncrypted = "bigFile.enc";

        byte[] buf = new byte[4096];
        int read = 0;
        long totalread = 0;

        byte[] oneMb = new byte[1024 * 1024]; // 1 MB

        log.debug("Generating {} bytes of random...", oneMb.length);
        new Random().nextBytes(oneMb);

        log.debug("Done.");

        long mbWanted = 8192; // 8 GB

        File biggerFile = tempDir.resolve(bigFileName).toFile();

        log.debug("Writing {} MB to file..", mbWanted);
        try (OutputStream os = Files.newOutputStream(biggerFile.toPath())) {
            for (long i = 0; i < mbWanted; i++) {
                os.write(oneMb);
            }
        }
        log.debug("Done.");

        // Perform read speed test
        Instant readStart = Instant.now();
        log.debug("Reading speed test");
        try (InputStream is =
                Files.newInputStream(tempDir.resolve(biggerFile.toPath()))) {
            while ((read = is.read(buf)) > 0) {
                totalread += read;
            }
        }
        log.debug("Read {}B in {} seconds", totalread, Duration.between(readStart, Instant.now()).toSeconds());


        log.debug("Encrypting");
        OutputStream destChaChaStream = Files.newOutputStream(tempDir.resolve(bigFileNameEncrypted));
        InputStream inputStream = Files.newInputStream(biggerFile.toPath());

        byte[] aad = Envelope.getAdditionalData(new byte[]{}, new byte[] {});
        byte[] secret = new byte[32];
        Crypto.getSecureRandom().nextBytes(secret);
        SecretKey cek = new SecretKeySpec(secret, "");
        try (CipherOutputStream cipherOutputStream = ChaChaCipher.initChaChaOutputStream(destChaChaStream, cek, aad)) {
            inputStream.transferTo(cipherOutputStream);
        }
        log.debug("Created {}", tempDir.resolve(bigFileNameEncrypted));

        // Perform decrypt speed test
        Instant decryptStart = Instant.now();
        log.debug("Decrypting {}", tempDir.resolve(bigFileNameEncrypted));

        read = 0;
        totalread = 0;
        try (CipherInputStream cis = ChaChaCipher.initChaChaInputStream(
                Files.newInputStream(tempDir.resolve(bigFileNameEncrypted)), cek, aad)) {
            while ((read = cis.read(buf)) > 0) {
                totalread += read;
            }
        }
        log.debug("Decrypted {}B in {} seconds", totalread, Duration.between(decryptStart, Instant.now()).toSeconds());

    }


}
