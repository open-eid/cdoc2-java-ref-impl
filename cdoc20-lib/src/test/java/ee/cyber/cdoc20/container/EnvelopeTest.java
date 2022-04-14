package ee.cyber.cdoc20.container;

import static org.junit.jupiter.api.Assertions.*;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

class EnvelopeTest {
    private static final Logger log = LoggerFactory.getLogger(EnvelopeTest.class);

    @SuppressWarnings("checkstyle:OperatorWrap")
    private final String aliceKeyPem = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MIGkAgEBBDAlhCJUAcquXTQoZ73awJa7izsXqUhjcPxXP0ybTDFJYuGMeJ5qCGRw\n" +
            "0RHaMUEJIPagBwYFK4EEACKhZANiAASV2VitdXFvs7OYIsnXMxe5I0boJlg4/shi\n" +
            "FW6PgwFWgARITC7ABMOmYKC4I9KRMVNhwU42287/N+IOt2GtEHvL1OmfJvI9283o\n" +
            "wiYVMt6Qq/6Fv4kO3IXqSVsV1ylA4jQ=\n" +
            "-----END EC PRIVATE KEY-----\n";

    @SuppressWarnings("checkstyle:OperatorWrap")
    private final String bobKeyPem = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MIGkAgEBBDAFxoHAdX8mU9cjiXOy46Gljmongxto0nHwRQs5cb93vIcysAaYLmhL\n" +
            "mH4DPqnSXJWgBwYFK4EEACKhZANiAAR5Yacpp5H4aBAIxkDtdBXcw/BFyMNEQu4B\n" +
            "LqnEv1cUVHROnhw3hAW63F3H2PI93ZzB/BT6+C+gOLt3XkCT/H3C9X1ZktCd5lS2\n" +
            "BmC8zN4UciwrTb68gt4ylKUCd5g30KY=\n" +
            "-----END EC PRIVATE KEY-----\n";


    byte[] fmkBuf =  new byte[Crypto.FMK_LEN_BYTES];
    KeyPair senderKeyPair;
    KeyPair recipientKeyPair;


    @BeforeEach
    public void initInputData()
            throws GeneralSecurityException, IOException {
        this.fmkBuf = Crypto.generateFileMasterKey();
        this.recipientKeyPair = ECKeys.loadFromPem(bobKeyPem);
        this.senderKeyPair = ECKeys.loadFromPem(aliceKeyPem);
    }

    // Mainly flatbuffers and friends
    @Test
    void testHeaderSerializationParse() throws IOException, GeneralSecurityException, CDocParseException {

        File payloadFile = new File(System.getProperty("java.io.tmpdir"), "payload-" + UUID.randomUUID() + ".txt");
        payloadFile.deleteOnExit();
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write("payload".getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();
        List<ECPublicKey> recipients = List.of((ECPublicKey) recipientKeyPair.getPublic());

        Envelope envelope = Envelope.prepare(fmkBuf, senderKeyPair, recipients);
        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        ByteArrayOutputStream headerOs = new ByteArrayOutputStream();

        //no exception is also good indication that parsing worked
        List<Details.EccRecipient> details = Envelope.parseHeader(new ByteArrayInputStream(resultBytes), headerOs);

        assertEquals(1, details.size());

        assertEquals(recipientPubKey, details.get(0).getRecipientPubKey());
        assertEquals(senderKeyPair.getPublic(), details.get(0).getSenderPubKey());


    }

    @Test
    void testContainer(@TempDir Path tempDir) throws IOException, GeneralSecurityException, CDocParseException {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";

        String payloadData = "payload-" + uuid;

        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        KeyPair aliceKeyPair = ECKeys.generateEcKeyPair();
        KeyPair bobKeyPair = ECKeys.generateEcKeyPair();

        ECPublicKey recipientPubKey = (ECPublicKey) bobKeyPair.getPublic();
        List<ECPublicKey> recipients = List.of(recipientPubKey);

        Envelope senderEnvelope = Envelope.prepare(fmkBuf, aliceKeyPair, recipients);
        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(List.of(payloadFile), dst);
            byte[] cdocContainerBytes = dst.toByteArray();

            assertTrue(cdocContainerBytes.length > 0);

            try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocContainerBytes)) {
                List<String> filesExtracted = Envelope.decrypt(bis, bobKeyPair, outDir);

                assertEquals(List.of(payloadFileName), filesExtracted);
                Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), payloadFileName);

                assertEquals(payloadData, Files.readString(payloadPath));
            }
        }
    }

    // comment out as running this test takes ~20seconds.
    // resources
    // test that near max size header can be created and parsed
    @Test
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

        KeyPair aliceKeyPair = ECKeys.generateEcKeyPair();
        KeyPair bobKeyPair = ECKeys.generateEcKeyPair();

        ECPublicKey bobPubKey = (ECPublicKey) bobKeyPair.getPublic();


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
                Envelope.prepare(fmkBuf, aliceKeyPair, Collections.nCopies((copies + 1), bobPubKey)).serializeHeader());

        assertTrue(exception.getMessage().contains("Header serialization failed"));

        Instant start = Instant.now();
        Envelope senderEnvelope = Envelope.prepare(fmkBuf, aliceKeyPair, Collections.nCopies((copies), bobPubKey));
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
