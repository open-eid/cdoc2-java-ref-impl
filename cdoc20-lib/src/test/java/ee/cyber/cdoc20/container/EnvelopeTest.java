package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.client.KeyCapsuleClient;
import ee.cyber.cdoc20.client.model.Capsule;
import ee.cyber.cdoc20.container.recipients.EccRecipient;
import ee.cyber.cdoc20.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc20.container.recipients.RSAServerKeyRecipient;
import ee.cyber.cdoc20.container.recipients.Recipient;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import ee.cyber.cdoc20.crypto.EncryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc20.crypto.PemTools;
import ee.cyber.cdoc20.crypto.RsaUtils;
import ee.cyber.cdoc20.fbs.header.Header;
import ee.cyber.cdoc20.fbs.header.RecipientRecord;
import ee.cyber.cdoc20.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc20.fbs.recipients.RSAPublicKeyCapsule;
import ee.cyber.cdoc20.fbs.recipients.SymmetricKeyCapsule;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.compress.utils.CountingInputStream;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc20.container.EnvelopeTestUtils.testContainer;
import static ee.cyber.cdoc20.fbs.header.Capsule.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// as tests create and write files, and set/read System Properties, then it's safer to run tests isolated
// some tests can be run parallel, but this is untested
@Isolated
@ExtendWith(MockitoExtension.class)
class EnvelopeTest {
    private static final Logger log = LoggerFactory.getLogger(EnvelopeTest.class);

    @SuppressWarnings("checkstyle:OperatorWrap")
    private final String bobKeyPem = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MIGkAgEBBDAFxoHAdX8mU9cjiXOy46Gljmongxto0nHwRQs5cb93vIcysAaYLmhL\n" +
            "mH4DPqnSXJWgBwYFK4EEACKhZANiAAR5Yacpp5H4aBAIxkDtdBXcw/BFyMNEQu4B\n" +
            "LqnEv1cUVHROnhw3hAW63F3H2PI93ZzB/BT6+C+gOLt3XkCT/H3C9X1ZktCd5lS2\n" +
            "BmC8zN4UciwrTb68gt4ylKUCd5g30KY=\n" +
            "-----END EC PRIVATE KEY-----\n";

    @Mock
    KeyCapsuleClient capsuleClientMock;

    Capsule capsuleData;

    // Mainly flatbuffers and friends
    @Test
    void testHeaderSerializationParse() throws Exception {

        KeyPair recipientKeyPair = PemTools.loadKeyPair(bobKeyPem);

        File payloadFile = new File(System.getProperty("java.io.tmpdir"), "payload-" + UUID.randomUUID() + ".txt");
        payloadFile.deleteOnExit();
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write("payload".getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();

        String keyLabel = "testHeaderSerializationParse";
        Envelope envelope = Envelope.prepare(
                List.of(EncryptionKeyMaterial.fromPublicKey(
                    recipientKeyPair.getPublic(), keyLabel, EncryptionKeyOrigin.FROM_PUBLIC_KEY)
                ), null);
        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        //no exception is also good indication that parsing worked
        List<Recipient> recipients = Envelope.parseHeader(new ByteArrayInputStream(resultBytes));

        assertEquals(1, recipients.size());

        var recipient = recipients.get(0);
        assertInstanceOf(EccRecipient.class, recipient);

        assertEquals(recipientPubKey, ((EccRecipient) recipient).getRecipientPubKey());
        assertNotNull(recipient.getRecipientKeyLabel());
        assertEquals(keyLabel, recipient.getRecipientKeyLabel());
    }

    @Test
    void testRsaSerialization(@TempDir Path tempDir) throws Exception {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());

        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        String keyLabel = "testRsaSerialization";
        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromPublicKey(
                publicKey, keyLabel, EncryptionKeyOrigin.FROM_PUBLIC_KEY)
            ),
            null
        );

        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] cdocBytes = dst.toByteArray();

        assertTrue(cdocBytes.length > 0);

        log.debug("available: {}", cdocBytes.length);

        byte[] fbsBytes = Envelope.readFBSHeader(new ByteArrayInputStream(cdocBytes));
        Header header = Envelope.deserializeFBSHeader(fbsBytes);

        assertNotNull(header);
        assertEquals(1, header.recipientsLength());

        RecipientRecord recipient = header.recipients(0);

        assertEquals(keyLabel, recipient.keyLabel());
        assertEquals(recipients_RSAPublicKeyCapsule, recipient.capsuleType());

        RSAPublicKeyCapsule rsaPublicKeyCapsule = (RSAPublicKeyCapsule) recipient.capsule(new RSAPublicKeyCapsule());
        assertNotNull(rsaPublicKeyCapsule);

        ByteBuffer rsaPubKeyBuf = rsaPublicKeyCapsule.recipientPublicKeyAsByteBuffer();
        assertNotNull(rsaPubKeyBuf);
        byte[] rsaPubKeyBytes = Arrays.copyOfRange(rsaPubKeyBuf.array(), rsaPubKeyBuf.position(), rsaPubKeyBuf.limit());
        PublicKey publicKeyOut = RsaUtils.decodeRsaPubKey(rsaPubKeyBytes);

        assertEquals(publicKey, publicKeyOut);
    }

    @Test
    void testEccServerSerialization(@TempDir Path tempDir) throws Exception {
        KeyPair recipientKeyPair = PemTools.loadKeyPair(bobKeyPem);

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) recipientKeyPair.getPublic();
        final String recipientKeyLabel = "testEccServerSerialization";

        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock");
        when(capsuleClientMock.storeCapsule(any())).thenReturn("SD1234567890");

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromPublicKey(
                recipientPubKey, recipientKeyLabel, EncryptionKeyOrigin.FROM_PUBLIC_KEY)
            ),
            capsuleClientMock
        );
        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        //no exception is also good indication that parsing worked
        List<Recipient> eccRecipients = Envelope.parseHeader(new ByteArrayInputStream(resultBytes));

        assertEquals(1, eccRecipients.size());

        assertInstanceOf(EccServerKeyRecipient.class, eccRecipients.get(0));

        EccServerKeyRecipient eccServerKeyRecipient = (EccServerKeyRecipient) eccRecipients.get(0);

        assertEquals(recipientPubKey, eccServerKeyRecipient.getRecipientPubKey());

        assertEquals("mock", eccServerKeyRecipient.getKeyServerId());
        assertEquals("SD1234567890", eccServerKeyRecipient.getTransactionId());
        assertEquals(recipientKeyLabel, eccServerKeyRecipient.getRecipientKeyLabel());
    }

    @Test
    void testRsaServerSerialization(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());

        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        final String recipientKeyLabel = "testRsaServerSerialization";

        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock_rsa");
        when(capsuleClientMock.storeCapsule(any())).thenReturn("KC1234567890123456789012");

        Envelope envelope = Envelope.prepare(
                List.of(EncryptionKeyMaterial.fromPublicKey(
                    publicKey, recipientKeyLabel, EncryptionKeyOrigin.FROM_PUBLIC_KEY)
                ),
            capsuleClientMock
        );
        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] resultBytes = dst.toByteArray();

        assertTrue(resultBytes.length > 0);

        //no exception is also good indication that parsing worked
        List<Recipient> recipients = Envelope.parseHeader(new ByteArrayInputStream(resultBytes));

        assertEquals(1, recipients.size());

        assertInstanceOf(RSAServerKeyRecipient.class, recipients.get(0));

        RSAServerKeyRecipient rsaServerKeyRecipient = (RSAServerKeyRecipient) recipients.get(0);

        assertEquals(publicKey, rsaServerKeyRecipient.getRecipientPubKey());

        assertEquals("mock_rsa", rsaServerKeyRecipient.getKeyServerId());
        assertEquals("KC1234567890123456789012", rsaServerKeyRecipient.getTransactionId());
        assertEquals(recipientKeyLabel, rsaServerKeyRecipient.getRecipientKeyLabel());

    }

    @Test
    void testSymmetricKeySerialization(@TempDir Path tempDir) throws Exception {
        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        SecretKey preSharedKey = new SecretKeySpec(secret, "");


        String keyLabel = "testSymmetricKeySerialization";
        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromSecret(
                preSharedKey, keyLabel, EncryptionKeyOrigin.FROM_SECRET)
            ),
            null
        );

        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] cdocBytes = dst.toByteArray();

        assertTrue(cdocBytes.length > 0);

        log.debug("available: {}", cdocBytes.length);

        byte[] fbsBytes = Envelope.readFBSHeader(new ByteArrayInputStream(cdocBytes));
        Header header = Envelope.deserializeFBSHeader(fbsBytes);

        assertNotNull(header);
        assertEquals(1, header.recipientsLength());

        RecipientRecord recipient = header.recipients(0);

        assertEquals(keyLabel, recipient.keyLabel());
        assertEquals(recipients_SymmetricKeyCapsule, recipient.capsuleType());

        SymmetricKeyCapsule symmetricKeyCapsule = (SymmetricKeyCapsule) recipient.capsule(new SymmetricKeyCapsule());
        assertNotNull(symmetricKeyCapsule);

        ByteBuffer saltBuf = symmetricKeyCapsule.saltAsByteBuffer();
        assertNotNull(saltBuf);
    }

    @Test
    void testPasswordKeySerialization(@TempDir Path tempDir) throws Exception {
        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        String password = "myplaintextpassword";
        String keyLabel = "testPBKDF2KeyFromPasswordSerialization";
        byte[] salt = Crypto.generateSaltForKey();
        SecretKey preSharedKey = Crypto.extractKeyMaterialFromPassword(password.toCharArray(), salt);

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromPassword(
                preSharedKey, keyLabel, EncryptionKeyOrigin.FROM_PASSWORD, salt)
            ),
            null
        );

        ByteArrayOutputStream dst = new ByteArrayOutputStream();
        envelope.encrypt(List.of(payloadFile), dst);

        byte[] cdocBytes = dst.toByteArray();

        assertTrue(cdocBytes.length > 0);

        log.debug("available: {}", cdocBytes.length);

        byte[] fbsBytes = Envelope.readFBSHeader(new ByteArrayInputStream(cdocBytes));
        Header header = Envelope.deserializeFBSHeader(fbsBytes);

        assertNotNull(header);
        assertEquals(1, header.recipientsLength());

        RecipientRecord recipient = header.recipients(0);

        assertEquals(keyLabel, recipient.keyLabel());
        assertEquals(recipients_PBKDF2Capsule, recipient.capsuleType());

        PBKDF2Capsule passwordKeyCapsule =
            (PBKDF2Capsule) recipient.capsule(new PBKDF2Capsule());
        assertNotNull(passwordKeyCapsule);

        ByteBuffer saltBuf = passwordKeyCapsule.saltAsByteBuffer();
        assertNotNull(saltBuf);
    }

    @Test
    void testECContainer(@TempDir Path tempDir) throws Exception {
        KeyPair bobKeyPair = PemTools.loadKeyPair(bobKeyPem);
        testContainer(tempDir, DecryptionKeyMaterial.fromKeyPair(bobKeyPair),
                "testECContainer", null);
    }

    @Test
    void testECServerScenario(@TempDir Path tempDir) throws Exception {
        KeyPair keyPair = PemTools.loadKeyPair(bobKeyPem);
        String transactionId = "KC1234567890123456789011";

        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock_ec_server");

        doAnswer(invocation -> {
            capsuleData = (Capsule) invocation.getArguments()[0];
            log.debug("storing capsule {}", capsuleData);
            return transactionId;
        }).when(capsuleClientMock).storeCapsule(any(Capsule.class));

        when(capsuleClientMock.getCapsule(transactionId)).thenAnswer((Answer<Optional<Capsule>>) invocation -> {
            log.debug("returning capsule {}", capsuleData);
            return Optional.of(capsuleData);
        });

        testContainer(tempDir, DecryptionKeyMaterial.fromKeyPair(keyPair), "testECContainer", capsuleClientMock);

        verify(capsuleClientMock, times(1)).storeCapsule(any());
        verify(capsuleClientMock, times(1)).getCapsule(transactionId);

        assertEquals(Capsule.CapsuleTypeEnum.ECC_SECP384R1, capsuleData.getCapsuleType());
        assertEquals(keyPair.getPublic(), EllipticCurve.SECP384R1.decodeFromTls(
                ByteBuffer.wrap(capsuleData.getRecipientId())));
        assertTrue(EllipticCurve.SECP384R1.isValidKey(
                    EllipticCurve.SECP384R1.decodeFromTls(
                        ByteBuffer.wrap(capsuleData.getEphemeralKeyMaterial())))
        );
    }

    @Test
    void testContainerUsingRSAKey(@TempDir Path tempDir) throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());
        KeyPair rsaKeyPair = generator.generateKeyPair();

        testContainer(tempDir, DecryptionKeyMaterial.fromKeyPair(rsaKeyPair), "testContainerUsingRSAKey", null);
    }

    @Test
    void testSymmetricKeyScenario(@TempDir Path tempDir) throws Exception {
        String label = "testSymmetricKeyScenario";
        byte[] secret = new byte[32];
        Crypto.getSecureRandom().nextBytes(secret);
        SecretKey key = new SecretKeySpec(secret, "");

        testContainer(tempDir, DecryptionKeyMaterial.fromSecretKey(label, key), label, null);
    }

    @Test
    void testPasswordKeyScenario(@TempDir Path tempDir) throws Exception {
        String password = "myplaintextpassword";
        String keyLabel = "testPBKDF2KeyFromPasswordSerialization";
        byte[] salt = Crypto.generateSaltForKey();
        SecretKey preSharedKey = Crypto.extractKeyMaterialFromPassword(password.toCharArray(), salt);

        testContainer(
            tempDir,
            DecryptionKeyMaterial.fromPassword(keyLabel, preSharedKey, salt),
            keyLabel,
            null
        );
    }

    @Test
    void testRsaServerScenario(@TempDir Path tempDir) throws Exception {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());
        KeyPair rsaKeyPair = generator.generateKeyPair();

        String transactionId = "KC1234567890123456789012";

        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock_rsa_server");

        doAnswer(invocation -> {
            capsuleData = (Capsule) invocation.getArguments()[0];
            log.debug("storing capsule {}", capsuleData);
            return transactionId;
        }).when(capsuleClientMock).storeCapsule(any(Capsule.class));

        when(capsuleClientMock.getCapsule(transactionId)).thenAnswer((Answer<Optional<Capsule>>) invocation -> {
            log.debug("returning capsule {}", capsuleData);
            return Optional.of(capsuleData);
        });

        testContainer(tempDir, DecryptionKeyMaterial.fromKeyPair(rsaKeyPair),
                "testContainerUsingRSAKey", capsuleClientMock);

        verify(capsuleClientMock, times(1)).storeCapsule(any());
        verify(capsuleClientMock, times(1)).getCapsule(transactionId);
        assertEquals(Capsule.CapsuleTypeEnum.RSA, capsuleData.getCapsuleType());

        assertEquals(rsaKeyPair.getPublic(), RsaUtils.decodeRsaPubKey(capsuleData.getRecipientId()));
        assertEquals(((RSAPublicKey)rsaKeyPair.getPublic()).getModulus().bitLength(),
                capsuleData.getEphemeralKeyMaterial().length * 8);
    }


    @Test
    @DisplayName("Check that already created files are removed, when mac check in ChaCha20Poly1305 fails")
    void testContainerWrongPoly1305Mac(@TempDir Path tempDir) throws Exception {
        KeyPair bobKeyPair = PemTools.loadKeyPair(bobKeyPem);
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

        var encKM = EncryptionKeyMaterial.fromPublicKey(
            bobKeyPair.getPublic(), "testContainerWrongPoly1305Mac", EncryptionKeyOrigin.FROM_PUBLIC_KEY
        );

        byte[] cdocContainerBytes = EnvelopeTestUtils.createContainer(payloadFile,
                payloadData.getBytes(StandardCharsets.UTF_8), encKM, List.of(biggerFile), null);

        log.debug("cdoc size: {}", cdocContainerBytes.length);

        //last 16 bytes are Poly1305 MAC, corrupt that
        cdocContainerBytes[cdocContainerBytes.length - 1] = (byte) 0xff;
        cdocContainerBytes[cdocContainerBytes.length - 2] = (byte) 0xfe;

        var ex = assertThrows(
            Exception.class,
            () -> EnvelopeTestUtils.checkContainerDecrypt(cdocContainerBytes, outDir,
                    DecryptionKeyMaterial.fromKeyPair(bobKeyPair),
                    List.of(payloadFileName), payloadFileName, payloadData, null)
        );

        assertInstanceOf(AEADBadTagException.class, ex.getCause());
        assertEquals("mac check in ChaCha20Poly1305 failed", ex.getCause().getMessage());

        assertNotNull(outDir.toFile().listFiles());
        //extracted files were deleted
        assertTrue(Arrays.stream(outDir.toFile().listFiles()).toList().isEmpty());
    }

    @Test
    void testThatIncompleteCDocFilesAreRemoved(@TempDir Path tempDir)
            throws IOException, GeneralSecurityException {
        KeyPair bobKeyPair = PemTools.loadKeyPair(bobKeyPem);
        UUID uuid = UUID.randomUUID();
        String payloadFileName = "-payload:" + uuid + ".txt"; //invalid
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();


        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        var encKM = EncryptionKeyMaterial.fromPublicKey(
            bobKeyPair.getPublic(), "blah", EncryptionKeyOrigin.FROM_PUBLIC_KEY
        );

        File cdocFile = tempDir.resolve("incomplete.cdoc").toFile();

        Files.createFile(cdocFile.toPath());
        assertTrue(cdocFile.exists());

        String overwrite = System.getProperty(CDocConfiguration.OVERWRITE_PROPERTY);
        System.setProperty(CDocConfiguration.OVERWRITE_PROPERTY, "true");
        try {
            var ex = assertThrows(
                    Exception.class,
                    () -> EnvelopeTestUtils.createContainerUsingCDocBuilder(cdocFile, payloadFile,
                            payloadData.getBytes(StandardCharsets.UTF_8), encKM, null, null)
            );

            assertFalse(cdocFile.exists());
        } finally {
            if (overwrite != null) {
                System.setProperty(CDocConfiguration.OVERWRITE_PROPERTY, overwrite);
            }
        }
    }

    // tar processing is ended after zero block has encountered. It is possible to add extra data after this and tar lib
    // won't process it. Verify that all data is processed and Poly1305 MAC is validated
    @Test
    void testTarWithExtraData(@TempDir Path tempDir) throws Exception {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(secret);
        SecretKey preSharedKey = new SecretKeySpec(secret, "");
        String keyLabel = "testTarWithExtraData";

        byte[] cdocBytes =  EnvelopeTestUtils.createContainer(
            payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8),
            EncryptionKeyMaterial.fromSecret(preSharedKey, keyLabel, EncryptionKeyOrigin.FROM_SECRET),
            null,
            null
        );

        assertTrue(cdocBytes.length > 0);

        log.debug("cdoc length: {}", cdocBytes.length);

        byte[] tarWithExtraDataPayload = EnvelopeTestUtils.createTarWithExtraData();
        byte[] newCdocBytes =
                EnvelopeTestUtils.replacePayload(cdocBytes, preSharedKey, keyLabel, tarWithExtraDataPayload);

        log.debug("CDOC size {}", newCdocBytes.length);

        CountingInputStream countingInputStream = new CountingInputStream(new ByteArrayInputStream(newCdocBytes));

        IOException ioex = assertThrows(IOException.class, () -> Envelope.list(
                    countingInputStream,
                    DecryptionKeyMaterial.fromSecretKey(keyLabel, preSharedKey), null
                ));

        assertEquals("Unexpected data after tar", ioex.getMessage());

        assertEquals(newCdocBytes.length, countingInputStream.getBytesRead());

        // Although IOException is thrown, it should not be reported if MAC is wrong
        // MAC check exception is thrown instead of "Unexpected data after tar"
        byte[] wrongPoly1305MacCdoc = Arrays.copyOf(newCdocBytes, newCdocBytes.length);
        wrongPoly1305MacCdoc[wrongPoly1305MacCdoc.length - 1] = (byte) 0xff; //corrupt MAC

        CountingInputStream wrongMacIs =
                new CountingInputStream(new ByteArrayInputStream(wrongPoly1305MacCdoc));

        IOException ex = assertThrows(IOException.class, () -> Envelope.list(
                wrongMacIs,
                DecryptionKeyMaterial.fromSecretKey(keyLabel, preSharedKey), null
        ));

        assertInstanceOf(AEADBadTagException.class, ex.getCause());
        assertEquals("mac check in ChaCha20Poly1305 failed", ex.getCause().getMessage());

        assertEquals(newCdocBytes.length, wrongMacIs.getBytesRead());
    }

    @Test
    void testIllegalTarEntryType(@TempDir Path tempDir) throws Exception {

        byte[] tarWithIllegalFileTypeBytes = EnvelopeTestUtils.createTarWithIllegalFileType();

        Path outDir = tempDir.resolve("testIllegalTarEntryType.out");
        Files.createDirectories(outDir);

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(secret);
        SecretKey preSharedKey = new SecretKeySpec(secret, "");


        String keyLabel = "testTarWithExtraData";


        byte[] cdocBytes =  EnvelopeTestUtils.createContainer(
            payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8),
            EncryptionKeyMaterial.fromSecret(preSharedKey, keyLabel, EncryptionKeyOrigin.FROM_SECRET),
            null,
            null
        );

        assertTrue(cdocBytes.length > 0);

        log.debug("original cdoc length: {}", cdocBytes.length);

        byte[] newCdocBytes =
                EnvelopeTestUtils.replacePayload(cdocBytes, preSharedKey, keyLabel, tarWithIllegalFileTypeBytes);
        log.debug("replaced payload");

        log.debug("modified CDOC size {}", newCdocBytes.length);

        CountingInputStream countingInputStream = new CountingInputStream(new ByteArrayInputStream(newCdocBytes));

        IOException ioex = assertThrows(IOException.class, () -> Envelope.decrypt(
                countingInputStream,
                DecryptionKeyMaterial.fromSecretKey(keyLabel, preSharedKey), outDir, null
        ));

        assertEquals("Tar entry with illegal type found", ioex.getMessage());

        // all cdoc bytes were processed and Poly1305 MAC checked
        assertEquals(newCdocBytes.length, countingInputStream.getBytesRead());

        //extracted files were deleted
        assertTrue(Arrays.stream(outDir.toFile().listFiles()).toList().isEmpty());



        // MAC check exception is thrown instead of "Unexpected data after tar"
        byte[] wrongPoly1305MacCdoc = Arrays.copyOf(newCdocBytes, newCdocBytes.length);
        wrongPoly1305MacCdoc[wrongPoly1305MacCdoc.length - 1] = (byte) 0xff; //corrupt MAC

        CountingInputStream wrongMacIs =
                new CountingInputStream(new ByteArrayInputStream(wrongPoly1305MacCdoc));

        IOException ex = assertThrows(IOException.class, () -> Envelope.decrypt(
                wrongMacIs,
                DecryptionKeyMaterial.fromSecretKey(keyLabel, preSharedKey), outDir, null
        ));

        assertInstanceOf(AEADBadTagException.class, ex.getCause());
        assertEquals("mac check in ChaCha20Poly1305 failed", ex.getCause().getMessage());

        assertEquals(newCdocBytes.length, wrongMacIs.getBytesRead());

        //extracted files were deleted
        assertTrue(Arrays.stream(outDir.toFile().listFiles()).toList().isEmpty());
    }


    // test that near max size header can be created and parsed
    @Test
    @Tag("slow")
    void testLongHeader(@TempDir Path tempDir) throws Exception {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "A";

        String payloadData = "";

        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        KeyPair bobKeyPair = PemTools.loadKeyPair(bobKeyPem);

        ECPublicKey bobPubKey = (ECPublicKey) bobKeyPair.getPublic();

        // Code to find the limit of max header
        int singleKeyLen = Envelope.prepare(
                List.of(EncryptionKeyMaterial.fromPublicKey(
                    bobPubKey, "longHeader", EncryptionKeyOrigin.FROM_PUBLIC_KEY)
                ), null)
            .serializeHeader().length;
        int twoKeyLen = Envelope.prepare(
                List.of(
                    EncryptionKeyMaterial.fromPublicKey(bobPubKey, "longHeader", EncryptionKeyOrigin.FROM_PUBLIC_KEY),
                    EncryptionKeyMaterial.fromPublicKey(
                        ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1).getPublic(),
                        "longHeader",
                        EncryptionKeyOrigin.FROM_PUBLIC_KEY
                    )
                ), null
            )
            .serializeHeader().length;

        // Seems that FBS adds overhead for arrays, as recipient_length grows, if recipients number grows
        final int fbsOverhead = 4;
        int recipientLength = twoKeyLen - singleKeyLen + fbsOverhead;
        int emptyHeaderLen = singleKeyLen - recipientLength;

        log.debug("empty header len:{}, single recipient len {}",
            emptyHeaderLen, singleKeyLen - recipientLength
        );

        int maxRecipientsNum = (Envelope.MAX_HEADER_LEN - emptyHeaderLen) / recipientLength;

        log.debug("Generating: {} EC key pairs. {} < {}",
            maxRecipientsNum,
            maxRecipientsNum * recipientLength + emptyHeaderLen, Envelope.MAX_HEADER_LEN);
        assertTrue(maxRecipientsNum * recipientLength + emptyHeaderLen < Envelope.MAX_HEADER_LEN);

        Map<PublicKey, String> keyLabelMap = new HashMap<>();
        Instant start = Instant.now();
        for  (int i = 1; i < maxRecipientsNum; i++) {
            keyLabelMap.put(ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1).getPublic(), "longHeader");
        }
        keyLabelMap.put(bobPubKey, "_bob_key_");

        List<EncryptionKeyMaterial> recipients = keyLabelMap.entrySet().stream()
                .map(entry -> EncryptionKeyMaterial.fromPublicKey(
                    entry.getKey(), entry.getValue(), EncryptionKeyOrigin.FROM_PUBLIC_KEY)
                )
                .collect(Collectors.toList()); //mutable list

        Instant end = Instant.now();
        log.debug("Generated {} EC keys in {}s", keyLabelMap.size(), end.getEpochSecond() - start.getEpochSecond());

        Instant prepareStart = Instant.now();
        Envelope senderEnvelope = Envelope.prepare(recipients, null);
        Instant prepareEnd = Instant.now();
        log.debug("Prepared {} EC sender keys in {}s", keyLabelMap.size(),
                prepareEnd.getEpochSecond() - prepareStart.getEpochSecond());

        Instant serializeStart = Instant.now();
        byte[] headerBuf = senderEnvelope.serializeHeader();
        Instant serializeEnd = Instant.now();
        log.debug("Recipients: {} header size: {}B in {}s", keyLabelMap.size(), headerBuf.length,
                serializeEnd.getEpochSecond() - serializeStart.getEpochSecond());

        //  test that serialization fails for oversize header
        recipients.add(EncryptionKeyMaterial.fromPublicKey(
            ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1).getPublic(),
            "longHeader+1",
            EncryptionKeyOrigin.FROM_PUBLIC_KEY)
        );

        Envelope prepare = Envelope.prepare(recipients, null);
        IllegalStateException exception =
            assertThrows(IllegalStateException.class, prepare::serializeHeader);

        assertTrue(exception.getMessage().contains("Header serialization failed"));

        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(List.of(payloadFile), dst);
            byte[] cdocContainerBytes = dst.toByteArray();

            assertTrue(cdocContainerBytes.length > 0);

            log.debug("CDOC container with {} recipients and minimal payload is {}B. ", keyLabelMap.size() - 1,
                    cdocContainerBytes.length);

            try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocContainerBytes)) {
                List<String> filesExtracted = Envelope.decrypt(bis, DecryptionKeyMaterial.fromKeyPair(bobKeyPair),
                        outDir, null);

                assertEquals(List.of(payloadFileName), filesExtracted);
                Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), payloadFileName);

                assertEquals(payloadData, Files.readString(payloadPath));
            }
        }
    }

    // test that over 8GB files can be encrypted/decrypted.
    // Over 8GB files are tar extension
    // Not all ChaCha implementation can handle big files
    // requires 16GB of free disk space on /tmp
    @Test
    @Tag("slow") // about 8 min, depends on IO speed
    void test8GBPlusFileContainer(@TempDir Path tempDir) throws Exception {

        // since generated file is random, zlib can't compress it effectively and
        // created cdoc might be bigger than original file
        long sixteenGB = (16 + 1) * 1024 * 1024 * 1024;
        if (tempDir.toFile().getUsableSpace() < sixteenGB) {
            log.error("Need {} B of free space, but only {} B available", sixteenGB, tempDir.toFile().getUsableSpace());
            fail("Not enough free disk space at " + tempDir);
        }

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        Files.write(payloadFile.toPath(), payloadData.getBytes(StandardCharsets.UTF_8));

        String bigFileName = "bigFile";

        byte[] oneMb = new byte[1024 * 1024]; // 1 MB

        log.debug("Generating {} bytes of random...", oneMb.length);
        new Random().nextBytes(oneMb);

        log.debug("Done.");

        long mbWanted = 8192 + 1; // 8,0001 GB
        // create over 8GB file (limit of standard tar to force use of POSIX bigFile extension headers)
        File biggerFile = tempDir.resolve(bigFileName).toFile();

        log.debug("Writing {} MB to file..", mbWanted);
        try (OutputStream os = Files.newOutputStream(biggerFile.toPath())) {
            for (long i = 0; i < mbWanted; i++) {
                os.write(oneMb);
            }
        }
        log.debug("Done.");

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        String label = "test8GBFileContainer";
        byte[] secret = new byte[32];
        Crypto.getSecureRandom().nextBytes(secret);
        SecretKey key = new SecretKeySpec(secret, "");

        Envelope envelope = Envelope.prepare(List.of(
            EncryptionKeyMaterial.fromSecret(key, label, EncryptionKeyOrigin.FROM_SECRET)),
            null
        );

        File bigDotCdoc = outDir.resolve("big.cdoc").toFile();

        log.debug("Encrypting big payload...");
        try (FileOutputStream dst = new FileOutputStream(bigDotCdoc)) {
            envelope.encrypt(List.of(payloadFile, biggerFile), dst);
        }
        log.debug("Done.");
        log.debug("Created {} {}B", bigDotCdoc, bigDotCdoc.length());

        log.debug("Decrypting {}", bigDotCdoc);
        try (FileInputStream cdoc = new FileInputStream(bigDotCdoc)) {
            // use list, instead of decrypt. Container is decrypted, but files are not extracted - save disk space
            List<ArchiveEntry> entryList =
                    Envelope.list(cdoc, DecryptionKeyMaterial.fromSecretKey(label, key), null);

            entryList.forEach(entry -> log.debug("{} {}", entry.getName(), entry.getSize()));

            assertEquals(2, entryList.size());
            assertEquals("bigFile", entryList.get(1).getName());
            assertEquals(mbWanted * oneMb.length, entryList.get(1).getSize());
        }
        log.debug("Done.");
    }
}
