package ee.cyber.cdoc20.container;

import static org.junit.jupiter.api.Assertions.*;

import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
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
    void testContainer() throws IOException, GeneralSecurityException, CDocParseException {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";

        String payloadData = "payload-" + uuid;

        File payloadFile = new File(System.getProperty("java.io.tmpdir"), payloadFileName);
        payloadFile.deleteOnExit();
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        Path outDir = Path.of(System.getProperty("java.io.tmpdir")).resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);
        outDir.toFile().deleteOnExit();

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
                payloadPath.toFile().deleteOnExit();

                assertEquals(payloadData, Files.readString(payloadPath));
            }
        }
    }
}
