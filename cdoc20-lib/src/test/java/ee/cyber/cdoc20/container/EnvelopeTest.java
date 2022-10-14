package ee.cyber.cdoc20.container;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;


import ee.cyber.cdoc20.container.recipients.EccRecipient;
import ee.cyber.cdoc20.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.util.ExtApiException;
import ee.cyber.cdoc20.util.KeyServerClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
public class EnvelopeTest {
    private static final Logger log = LoggerFactory.getLogger(EnvelopeTest.class);

    @SuppressWarnings("checkstyle:OperatorWrap")
    private final String bobKeyPem = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MIGkAgEBBDAFxoHAdX8mU9cjiXOy46Gljmongxto0nHwRQs5cb93vIcysAaYLmhL\n" +
            "mH4DPqnSXJWgBwYFK4EEACKhZANiAAR5Yacpp5H4aBAIxkDtdBXcw/BFyMNEQu4B\n" +
            "LqnEv1cUVHROnhw3hAW63F3H2PI93ZzB/BT6+C+gOLt3XkCT/H3C9X1ZktCd5lS2\n" +
            "BmC8zN4UciwrTb68gt4ylKUCd5g30KY=\n" +
            "-----END EC PRIVATE KEY-----\n";

    @Mock KeyServerClient keyServerClientMock;



    // Mainly flatbuffers and friends
    @Test
    void testHeaderSerializationParse() throws IOException, GeneralSecurityException, CDocParseException {

        KeyPair recipientKeyPair = ECKeys.loadFromPem(bobKeyPem);


        File payloadFile = new File(System.getProperty("java.io.tmpdir"), "payload-" + UUID.randomUUID() + ".txt");
        payloadFile.deleteOnExit();
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write("payload".getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();
        List<ECPublicKey> recipients = List.of((ECPublicKey) recipientKeyPair.getPublic());


        Envelope envelope = Envelope.prepare(recipients);
        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        ByteArrayOutputStream headerOs = new ByteArrayOutputStream();

        //no exception is also good indication that parsing worked
        List<EccRecipient> details = Envelope.parseHeader(new ByteArrayInputStream(resultBytes), headerOs);

        assertEquals(1, details.size());

        assertEquals(recipientPubKey, details.get(0).getRecipientPubKey());
        assertNotNull(details.get(0).getRecipientPubKeyLabel());
        assertTrue(details.get(0).getRecipientPubKeyLabel().startsWith("ec_pub_key"));
    }

    @Test
    void testEccServerSerialization(@TempDir Path tempDir) throws IOException, GeneralSecurityException,
            CDocParseException, ExtApiException {
        KeyPair recipientKeyPair = ECKeys.loadFromPem(bobKeyPem);

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();
        List<ECPublicKey> recipients = List.of((ECPublicKey) recipientKeyPair.getPublic());

        when(keyServerClientMock.getServerIdentifier()).thenReturn("mock");
        when(keyServerClientMock.storeSenderKey(any(), any())).thenReturn("SD1234567890");

        Envelope envelope = Envelope.prepare(recipients, keyServerClientMock);
        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        ByteArrayOutputStream headerOs = new ByteArrayOutputStream();

        //no exception is also good indication that parsing worked
        List<EccRecipient> eccRecipients =
                Envelope.parseHeader(new ByteArrayInputStream(resultBytes), headerOs);

        assertEquals(1, eccRecipients.size());



        assertInstanceOf(EccServerKeyRecipient.class, eccRecipients.get(0));

        EccServerKeyRecipient details = (EccServerKeyRecipient) eccRecipients.get(0);

        assertEquals(recipientPubKey, details.getRecipientPubKey());

        assertEquals("mock", details.getKeyServerId());
        assertEquals("SD1234567890", details.getTransactionId());
        assertNotNull(details.getRecipientPubKeyLabel());
        assertTrue(details.getRecipientPubKeyLabel().startsWith("ec_pub_key"));

    }


    @Test
    void testContainer(@TempDir Path tempDir) throws IOException, GeneralSecurityException, CDocParseException {
        KeyPair bobKeyPair = ECKeys.loadFromPem(bobKeyPem);
        testContainer(tempDir, bobKeyPair);
    }

    @Test
    @DisplayName("Check that already created files are removed, when mac check in ChaCha20Poly1305 fails")
    void testContainerWrongPoly1305Mac(@TempDir Path tempDir) throws IOException, GeneralSecurityException {
        KeyPair bobKeyPair = ECKeys.loadFromPem(bobKeyPem);
        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        byte[] bytes = new byte[1024];

        int bytesWanted = 8 * 1024;
        // create bigger file, so that payload file is written to disk, before MAC check
        File biggerFile = tempDir.resolve("biggerFile").toFile();
        try (OutputStream os = Files.newOutputStream(biggerFile.toPath())) {
            for (int i = 0; i <= bytesWanted; i++) {
                new Random().nextBytes(bytes);
                os.write(bytes);
            }
        }

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        byte[] cdocContainerBytes = createContainer(payloadFile, payloadData.getBytes(StandardCharsets.UTF_8),
                (ECPublicKey) bobKeyPair.getPublic(), List.of(biggerFile));

        log.debug("cdoc size: {}", cdocContainerBytes.length);

        //last 16 bytes are Poly1305 MAC, corrupt that
        cdocContainerBytes[cdocContainerBytes.length - 1] = (byte) 0xff;
        cdocContainerBytes[cdocContainerBytes.length - 2] = (byte) 0xfe;

        IOException ex = assertThrows(IOException.class, () -> checkContainerDecrypt(cdocContainerBytes, outDir,
                bobKeyPair, List.of(payloadFileName), payloadFileName, payloadData));

        assertInstanceOf(javax.crypto.AEADBadTagException.class, ex.getCause());

        //extracted files were deleted
        assertTrue(Arrays.stream(outDir.toFile().listFiles()).toList().isEmpty());



    }

    /**
     * Creates payloadFile, adds payloadData to payloadFile and creates encrypted container for recipientPubKey
     * @param payloadFile input payload file to be created and added to contaier
     * @param payloadData data to be written to payloadFile
     * @param recipientPubKey created container can be decrypted with recipientPubKey private part
     * @param additionalFiles optional additional file to add
     * @return created container as byte[]
     * @throws IOException if IOException happens
     * @throws GeneralSecurityException if GeneralSecurityException happens
     */
    public byte[] createContainer(File payloadFile, byte[] payloadData, ECPublicKey recipientPubKey,
                                  List<File> additionalFiles) throws IOException, GeneralSecurityException {

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData);
        }

        List<ECPublicKey> recipients = List.of(recipientPubKey);

        List<File> files = new LinkedList<>();
        files.add(payloadFile);
        if (additionalFiles != null) {
            files.addAll(additionalFiles);
        }

        byte[] cdocContainerBytes;
        Envelope senderEnvelope = Envelope.prepare(recipients);
        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(files, dst);
            cdocContainerBytes = dst.toByteArray();
        }
        assertNotNull(cdocContainerBytes);
        assertTrue(cdocContainerBytes.length > 0);
        return cdocContainerBytes;
    }

    public void testContainer(Path tempDir, KeyPair bobKeyPair)
            throws IOException, GeneralSecurityException, CDocParseException {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();


        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        byte[] cdocContainerBytes = createContainer(payloadFile,
                payloadData.getBytes(StandardCharsets.UTF_8), (ECPublicKey) bobKeyPair.getPublic(), null);

        assertTrue(cdocContainerBytes.length > 0);

        checkContainerDecrypt(cdocContainerBytes, outDir, bobKeyPair,
                List.of(payloadFileName), payloadFileName, payloadData);
    }

    public void checkContainerDecrypt(byte[] cdocBytes, Path outDir, KeyPair recipientKeyPair,
                                      List<String> expectedFilesExtracted,
                                      String payloadFileName, String expectedPayloadData)
            throws IOException, GeneralSecurityException, CDocParseException {

        try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocBytes)) {
            List<String> filesExtracted = Envelope.decrypt(bis, recipientKeyPair, outDir);

            assertEquals(expectedFilesExtracted, filesExtracted);
            Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), payloadFileName);

            assertEquals(expectedPayloadData, Files.readString(payloadPath));
        }

    }

    // test that near max size header can be created and parsed
    //@Disabled("testLongHeader is disabled as running it takes ~30seconds.")
    @Test
    @Tag("slow")
    void testLongHeader(@TempDir Path tempDir) throws IOException, GeneralSecurityException, CDocParseException {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";

        String payloadData = "payload-" + uuid;

        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        KeyPair bobKeyPair = ECKeys.loadFromPem(bobKeyPem);

        ECPublicKey bobPubKey = (ECPublicKey) bobKeyPair.getPublic();

// Code to find the limit of max header
//        int copies = Envelope.MAX_HEADER_LEN/285;
//        int length = 0;
//        do {
//            length = Envelope.prepare(fmkBuf, aliceKeyPair, Collections.nCopies(++copies, bobPubKey))
//                    .serializeHeader().length;
//            log.debug("{} size {}", copies, length);
//        } while (length < Envelope.MAX_HEADER_LEN);
//
//       Envelope senderEnvelope = Envelope.prepare(fmkBuf, aliceKeyPair, Collections.nCopies((copies-1), bobPubKey));
//        log.debug("Recipients: {} header size: {}B", copies-1, senderEnvelope.serializeHeader().length);

        //max number copies that fits in max_header_len
        int copies = 3691; // 3691 ECCPublicKey recipients is 1048296B


        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
                Envelope.prepare(Collections.nCopies((copies + 1), bobPubKey)).serializeHeader());

        assertTrue(exception.getMessage().contains("Header serialization failed"));

        Instant start = Instant.now();
        Envelope senderEnvelope = Envelope.prepare(Collections.nCopies((copies), bobPubKey));
        Instant end = Instant.now();
        log.debug("Ran: {}s", end.getEpochSecond() - start.getEpochSecond());

        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(List.of(payloadFile), dst);
            byte[] cdocContainerBytes = dst.toByteArray();

            assertTrue(cdocContainerBytes.length > 0);

            log.debug("CDOC container with {} recipients and almost empty payload is {}B", copies,
                    cdocContainerBytes.length);

            try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocContainerBytes)) {
                List<String> filesExtracted = Envelope.decrypt(bis, bobKeyPair, outDir);

                assertEquals(List.of(payloadFileName), filesExtracted);
                Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), payloadFileName);

                assertEquals(payloadData, Files.readString(payloadPath));
            }
        }
    }

}
