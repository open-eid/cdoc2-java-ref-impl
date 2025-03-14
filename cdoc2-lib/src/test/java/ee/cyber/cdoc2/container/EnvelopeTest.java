package ee.cyber.cdoc2.container;

import ee.cyber.cdoc2.CDocBuilder;
import ee.cyber.cdoc2.TestLifecycleLogger;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.container.recipients.EccRecipient;
import ee.cyber.cdoc2.container.recipients.EccServerKeyRecipient;
import ee.cyber.cdoc2.container.recipients.Recipient;
import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.RsaUtils;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.client.KeyCapsuleClient;
import ee.cyber.cdoc2.client.model.Capsule;
import ee.cyber.cdoc2.container.recipients.RSAServerKeyRecipient;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.EstEncKeyMaterialBuilder;
import ee.cyber.cdoc2.fbs.header.Header;
import ee.cyber.cdoc2.fbs.header.RecipientRecord;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;
import ee.cyber.cdoc2.fbs.recipients.PBKDF2Capsule;
import ee.cyber.cdoc2.fbs.recipients.RSAPublicKeyCapsule;
import ee.cyber.cdoc2.fbs.recipients.SymmetricKeyCapsule;

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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import ee.cyber.cdoc2.mobileid.MIDTestData;
import ee.cyber.cdoc2.services.Services;
import ee.cyber.cdoc2.services.ServicesBuilder;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.io.input.CountingInputStream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.ClientConfigurationUtil.initKeySharesTestEnvConfiguration;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.OVERWRITE_PROPERTY;
import static ee.cyber.cdoc2.KeyUtil.createKeyPair;
import static ee.cyber.cdoc2.KeyUtil.createPublicKey;
import static ee.cyber.cdoc2.KeyUtil.createSecretKey;
import static ee.cyber.cdoc2.KeyUtil.getKeyPairRsaInstance;
import static ee.cyber.cdoc2.container.EnvelopeTestUtils.checkContainerDecrypt;
import static ee.cyber.cdoc2.container.EnvelopeTestUtils.createKeyLabelParams;
import static ee.cyber.cdoc2.container.EnvelopeTestUtils.getPublicKeyLabelParams;
import static ee.cyber.cdoc2.container.EnvelopeTestUtils.testContainer;
import static ee.cyber.cdoc2.container.EnvelopeTestUtils.testContainerWithKeyShares;
import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.createSemanticsIdentifier;
import static ee.cyber.cdoc2.fbs.header.Capsule.*;
import static ee.cyber.cdoc2.fbs.header.Capsule.recipients_PBKDF2Capsule;
import static ee.cyber.cdoc2.smartid.SmartIdClientTest.getDemoEnvConfiguration;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
class EnvelopeTest implements TestLifecycleLogger {
    private static final Logger log = LoggerFactory.getLogger(EnvelopeTest.class);

    private static KeyLabelParams bobKeyLabelParams;

    @Mock
    KeyCapsuleClient capsuleClientMock;

    @Mock
    KeySharesClient mockKeySharesClient1;

    @Mock
    KeySharesClient mockKeySharesClient2;

    @Captor
    ArgumentCaptor<KeyShare> keyShareCaptor1;

    @Captor
    ArgumentCaptor<KeyShare> keyShareCaptor2;

    KeySharesClientFactory sharesClientFactory;

    Capsule capsuleData;

    @BeforeAll
    static void init() {
        bobKeyLabelParams = getPublicKeyLabelParams("bobKeyPem");
    }

    void setupKeyShareClientMocks() throws Exception {
        KeySharesConfiguration configuration = initKeySharesTestEnvConfiguration();
        sharesClientFactory = new KeySharesClientHelper(
            List.of(mockKeySharesClient1, mockKeySharesClient2),
            configuration
        );

        List<String> keySharesServersUrls = configuration.getKeySharesServersUrls().stream().toList();
        assertTrue(keySharesServersUrls.size() >= 2);
        when(mockKeySharesClient1.getServerIdentifier()).thenReturn(keySharesServersUrls.get(0));
        when(mockKeySharesClient2.getServerIdentifier()).thenReturn(keySharesServersUrls.get(1));

        when(mockKeySharesClient1.storeKeyShare(any())).thenReturn("shareId1");
        when(mockKeySharesClient2.storeKeyShare(any())).thenReturn("shareId2");
    }

    Services getMockCdoc2Services() throws Exception {
        setupKeyShareClientMocks();

        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock");
        when(capsuleClientMock.storeCapsule(any())).thenReturn("SD1234567890");

        Services services = new ServicesBuilder()
            .register(KeySharesClientFactory.class, sharesClientFactory, null)
            .register(KeyCapsuleClient.class, capsuleClientMock, null)
            .build();
        return services;
    }

    // Mainly flatbuffers and friends
    @Test
    void testHeaderSerializationParse() throws Exception {
        PublicKey publicKey = createPublicKey();

        File payloadFile = new File(System.getProperty("java.io.tmpdir"), "payload-" + UUID.randomUUID() + ".txt");
        payloadFile.deleteOnExit();
        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write("payload".getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) publicKey;

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial
                .fromPublicKey(publicKey, bobKeyLabelParams)),
            null, null
        );
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

        KeyPairGenerator generator = getKeyPairRsaInstance();
        generator.initialize(2048, SecureRandom.getInstanceStrong());

        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromPublicKey(
                publicKey, getPublicKeyLabelParams())
            ),
            null, null
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
        PublicKey publicKey = createPublicKey();

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        ECPublicKey recipientPubKey = (ECPublicKey) publicKey;

        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock");
        when(capsuleClientMock.storeCapsule(any())).thenReturn("SD1234567890");

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial
                .fromPublicKey(recipientPubKey, bobKeyLabelParams)),
            capsuleClientMock, null
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
    }

    @Test
    void testRsaServerSerialization(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator generator = getKeyPairRsaInstance();
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


        when(capsuleClientMock.getServerIdentifier()).thenReturn("mock_rsa");
        when(capsuleClientMock.storeCapsule(any())).thenReturn("KC1234567890123456789012");

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromPublicKey(
                publicKey, getPublicKeyLabelParams())
            ),
            capsuleClientMock, null
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

        SecretKey preSharedKey = createSecretKey();

        String keyLabel = "testSymmetricKeySerialization";
        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromSecret(preSharedKey, keyLabel)),
            null, null
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

        String password = "myPlainTextPassword";
        String keyLabel = "testPBKDF2KeyFromPasswordSerialization";

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial
                .fromPassword(password.toCharArray(), keyLabel)),
            null, null
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

        assertEquals(recipients_PBKDF2Capsule, recipient.capsuleType());

        PBKDF2Capsule passwordKeyCapsule = (PBKDF2Capsule) recipient.capsule(new PBKDF2Capsule());
        assertNotNull(passwordKeyCapsule);

        ByteBuffer saltBuf = passwordKeyCapsule.saltAsByteBuffer();
        assertNotNull(saltBuf);
    }

    @Test
    void testKeySharesSerializationWithSmartId(@TempDir Path tempDir) throws Exception {
        AuthenticationIdentifier.AuthenticationType authType
            = AuthenticationIdentifier.AuthenticationType.SID;
        AuthenticationIdentifier keyLabel = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier("30303039914"), authType

        );

        testKeySharesSerialization(tempDir, keyLabel, authType, "30303039914");
    }

    @Test
    void testKeySharesSerializationWithMobileId(@TempDir Path tempDir) throws Exception {
        AuthenticationIdentifier.AuthenticationType authType
            = AuthenticationIdentifier.AuthenticationType.MID;
        AuthenticationIdentifier keyLabel = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier("51307149560"), authType

        );

        testKeySharesSerialization(tempDir, keyLabel, authType, "51307149560");
    }

    @Test
    void testECContainer(@TempDir Path tempDir) throws Exception {
        KeyPair bobKeyPair = createKeyPair();
        testContainer(tempDir, DecryptionKeyMaterial.fromKeyPair(bobKeyPair),
            "testECContainer", null);
    }

    @Test
    void testECServerScenario(@TempDir Path tempDir) throws Exception {
        KeyPair keyPair = createKeyPair();
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
        Assertions.assertEquals(keyPair.getPublic(), EllipticCurve.SECP384R1.decodeFromTls(
            ByteBuffer.wrap(capsuleData.getRecipientId())));
        assertTrue(EllipticCurve.SECP384R1.isValidKey(
            EllipticCurve.SECP384R1.decodeFromTls(
                ByteBuffer.wrap(capsuleData.getEphemeralKeyMaterial())))
        );
    }

    @Test
    void testContainerUsingRSAKey(@TempDir Path tempDir) throws Exception {

        KeyPairGenerator generator = getKeyPairRsaInstance();
        generator.initialize(2048, SecureRandom.getInstanceStrong());
        KeyPair rsaKeyPair = generator.generateKeyPair();

        testContainer(tempDir, DecryptionKeyMaterial.fromKeyPair(rsaKeyPair), "testContainerUsingRSAKey", null);
    }

    @Test
    void testSymmetricKeyScenario(@TempDir Path tempDir) throws Exception {
        String label = "testSymmetricKeyScenario";
        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(secret);
        SecretKey key = new SecretKeySpec(secret, "");

        testContainer(tempDir, DecryptionKeyMaterial.fromSecretKey(key, label), label, null);
    }

    @Test
    void testSymmetricKeyScenarioWithFormattedKeyLabel(@TempDir Path tempDir) throws Exception {
        String label = "testSymmetricKeyScenario";
        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(secret);
        SecretKey key = new SecretKeySpec(secret, "");

        setUpKeyLabelFormat(true);

        testContainer(
            tempDir,
            DecryptionKeyMaterial.fromSecretKey(key, label),
            label,
            null
        );
    }

    @Test
    void testPasswordKeyScenario(@TempDir Path tempDir) throws Exception {
        String password = "myPlainTextPassword";
        String keyLabel = "testPBKDF2KeyFromPasswordSerialization";

        testContainer(
            tempDir,
            DecryptionKeyMaterial.fromPassword(password.toCharArray(), keyLabel),
            keyLabel,
            null
        );
    }

    @Test
    void testKeySharesScenarioWithSmartId(@TempDir Path tempDir) throws Exception {
        // SID demo env that authenticates automatically
        setupKeyShareClientMocks();

        AuthenticationIdentifier.AuthenticationType authType
            = AuthenticationIdentifier.AuthenticationType.SID;
        String idCode = "30303039914";

        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier(idCode), authType
        );

        EnvelopeTestUtils.DecryptionData decryptionData = testContainerWithKeyShares(
            tempDir,
            authIdentifier,
            authIdentifier,
            sharesClientFactory
        );

        verifyMockedKeyShareClients();

        //TODO: RM-4756, mock SmartIdClient
        SmartIdClient smartIdClient = new SmartIdClient(getDemoEnvConfiguration());
        Services services = new ServicesBuilder()
            .register(KeySharesClientFactory.class, sharesClientFactory, null)
            .register(SmartIdClient.class, smartIdClient, null)
            .build();

        checkContainerDecrypt(
            decryptionData.cdocContainerBytes(),
            decryptionData.outDir(),
            decryptionData.decryptionKeyMaterial(),
            List.of(decryptionData.payloadFileName()),
            decryptionData.payloadFileName(),
            decryptionData.payloadData(),
            services
        );
    }

    @Test
    void testKeySharesScenarioWithMobileId(@TempDir Path tempDir) throws Exception {
        // MID demo env that authenticates automatically
        setupKeyShareClientMocks();
        String idCode = "51307149560";
        AuthenticationIdentifier encAuthIdentifier = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier(idCode),
            AuthenticationIdentifier.AuthenticationType.MID
        );
        AuthenticationIdentifier decryptAuthIdentifier = AuthenticationIdentifier.forMidDecryption(
            createSemanticsIdentifier(idCode),
            "+37269930366"
        );

        EnvelopeTestUtils.DecryptionData decryptionData = testContainerWithKeyShares(
            tempDir,
            encAuthIdentifier,
            decryptAuthIdentifier,
            sharesClientFactory
        );

        verifyMockedKeyShareClients();

        //  TODO: RM-4756, mock MobileIdClient
        MobileIdClient midClient = MIDTestData.getDemoEnvClient();

        Services services = new ServicesBuilder()
            .register(KeySharesClientFactory.class, sharesClientFactory, null)
            .register(MobileIdClient.class, midClient, null)
            .build();

        checkContainerDecrypt(
            decryptionData.cdocContainerBytes(),
            decryptionData.outDir(),
            decryptionData.decryptionKeyMaterial(),
            List.of(decryptionData.payloadFileName()),
            decryptionData.payloadFileName(),
            decryptionData.payloadData(),
            services
        );
    }

    @Test
    void testReEncryptionScenario(@TempDir Path tempDir) throws Exception {
        // encrypt initial cdoc2 document
        UUID uuid = UUID.randomUUID();

        String payloadFileNameWithoutExtension = "payload-" + uuid;
        String payloadTxtFileName = payloadFileNameWithoutExtension + ".txt";
        String outputCdocFileName = payloadFileNameWithoutExtension + ".cdoc2";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadTxtFileName).toFile();

        SecretKey preSharedKey = createSecretKey();
        String secretKeyLabel = "symmetricKeyFromSecretSerialization";

        EncryptionKeyMaterial encryptionKeyMaterial =
            EncryptionKeyMaterial.fromSecret(preSharedKey, secretKeyLabel);

        byte[] cdoc2ContainerBytes = EnvelopeTestUtils.createContainer(
            payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8),
            encryptionKeyMaterial,
            null,
            null
        );

        // run re-encryption flow
        Path destinationDir = tempDir.resolve("out");
        Files.createDirectories(destinationDir);
        File outputCDocFile = destinationDir.resolve(outputCdocFileName).toFile();

        String password = "myPlainTextPassword";
        String passwordKeyLabel = "testPBKDF2KeyFromPasswordSerialization";

        EncryptionKeyMaterial reEncryptionKeyMaterial = EncryptionKeyMaterial
            .fromPassword(password.toCharArray(), passwordKeyLabel);

        try (ByteArrayInputStream cdocIs = new ByteArrayInputStream(cdoc2ContainerBytes);
             OutputStream outputCDocOs = new FileOutputStream(outputCDocFile)) {

            EnvelopeTestUtils.reEncryptContainer(
                cdocIs,
                DecryptionKeyMaterial.fromSecretKey(preSharedKey, encryptionKeyMaterial.getLabel()),
                outputCDocOs,
                reEncryptionKeyMaterial,
                destinationDir,
                null
            );
        }

        // ensure that re-encrypted container is decipherable
        assertDoesNotThrow(
            () ->  checkContainerDecrypt(
                Files.readAllBytes(outputCDocFile.toPath()),
                destinationDir,
                DecryptionKeyMaterial.fromPassword(password.toCharArray(), passwordKeyLabel),
                List.of(payloadTxtFileName),
                payloadTxtFileName,
                payloadData,
                null
            )
        );
    }

    @Test
    void testReEncryptionScenarioWithMobileId(@TempDir Path tempDir) throws Exception {
        // encrypt initial cdoc2 document
        setupKeyShareClientMocks();
        String idCode = "60001017869";
        AuthenticationIdentifier encAuthIdentifier = AuthenticationIdentifier.forKeyShares(
            createSemanticsIdentifier(idCode),
            AuthenticationIdentifier.AuthenticationType.MID
        );
        AuthenticationIdentifier decryptAuthIdentifier = AuthenticationIdentifier.forMidDecryption(
            createSemanticsIdentifier(idCode),
            "+37268000769"
        );

        EnvelopeTestUtils.DecryptionData decryptionData = testContainerWithKeyShares(
            tempDir,
            encAuthIdentifier,
            decryptAuthIdentifier,
            sharesClientFactory
        );

        verify(mockKeySharesClient1).storeKeyShare(keyShareCaptor1.capture());
        verify(mockKeySharesClient2).storeKeyShare(keyShareCaptor2.capture());

        KeyShare keyShare1 = keyShareCaptor1.getValue();
        KeyShare keyShare2 = keyShareCaptor2.getValue();

        NonceResponse nonce1 = new NonceResponse().nonce("nonce01nonce01");
        NonceResponse nonce2 = new NonceResponse().nonce("nonce02nonce02");

        when(mockKeySharesClient1.getKeyShare(any(), any(), any())).thenReturn(Optional.of(keyShare1));
        when(mockKeySharesClient2.getKeyShare(any(), any(), any())).thenReturn(Optional.of(keyShare2));


        when(mockKeySharesClient1.createKeyShareNonce(any())).thenReturn(nonce1);
        when(mockKeySharesClient2.createKeyShareNonce(any())).thenReturn(nonce2);

        //  TODO: RM-4756, mock MobileIdClient
        MobileIdClient midClient = MIDTestData.getDemoEnvClient();

        Services services = new ServicesBuilder()
            .register(KeySharesClientFactory.class, sharesClientFactory, null)
            .register(MobileIdClient.class, midClient, null)
            .build();

        // run re-encryption flow
        Path destinationDir = tempDir.resolve("out");
        Files.createDirectories(destinationDir);

        String outputCdocFileName = decryptionData.payloadFileName() + ".cdoc2";
        File outputCDocFile = destinationDir.resolve(outputCdocFileName).toFile();

        String password = "myPlainTextPassword";
        String passwordKeyLabel = "testPBKDF2KeyFromPasswordSerialization";

        EncryptionKeyMaterial reEncryptionKeyMaterial = EncryptionKeyMaterial
            .fromPassword(password.toCharArray(), passwordKeyLabel);

        try (ByteArrayInputStream cdocIs = new ByteArrayInputStream(decryptionData.cdocContainerBytes());
             OutputStream outputCDocOs = new FileOutputStream(outputCDocFile)) {

            Envelope.reEncrypt(
                cdocIs,
                decryptionData.decryptionKeyMaterial(),
                outputCDocOs,
                reEncryptionKeyMaterial,
                destinationDir,
                services
            );
        }

        // ensure that re-encrypted container is decipherable
        assertDoesNotThrow(
            () -> checkContainerDecrypt(
                Files.readAllBytes(outputCDocFile.toPath()),
                destinationDir,
                DecryptionKeyMaterial.fromPassword(password.toCharArray(), passwordKeyLabel),
                List.of(decryptionData.payloadFileName()),
                decryptionData.payloadFileName(),
                decryptionData.payloadData(),
                null
            )
        );
    }

    @Test
    void testRsaServerScenario(@TempDir Path tempDir) throws Exception {

        KeyPairGenerator generator = getKeyPairRsaInstance();
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


    /**
     * Disable on Windows, because deleting the temp file by cdoc2 and junit concurrently fails
     * @param tempDir
     * @throws Exception
     */
    @DisabledOnOs(OS.WINDOWS)
    @Test
    @DisplayName("Check that already created files are removed, when mac check in ChaCha20Poly1305 fails")
    void testContainerWrongPoly1305Mac(@TempDir Path tempDir) throws Exception {
        KeyPair bobKeyPair = createKeyPair();
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

        var encKM = EncryptionKeyMaterial
            .fromPublicKey(bobKeyPair.getPublic(), bobKeyLabelParams);

        byte[] cdocContainerBytes = EnvelopeTestUtils.createContainer(payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8), encKM, List.of(biggerFile), null);

        log.debug("cdoc size: {}", cdocContainerBytes.length);

        //last 16 bytes are Poly1305 MAC, corrupt that
        cdocContainerBytes[cdocContainerBytes.length - 1] = (byte) 0xff;
        cdocContainerBytes[cdocContainerBytes.length - 2] = (byte) 0xfe;

        var ex = assertThrows(
            Exception.class,
            () -> checkContainerDecrypt(cdocContainerBytes, outDir,
                DecryptionKeyMaterial.fromKeyPair(bobKeyPair),
                List.of(payloadFileName), payloadFileName, payloadData, null)
        );

        assertInstanceOf(AEADBadTagException.class, ex.getCause());
        assertEquals("mac check in ChaCha20Poly1305 failed", ex.getCause().getMessage());

        assertNotNull(outDir.toFile().listFiles());
        //extracted files were deleted
        assertTrue(Arrays.stream(outDir.toFile().listFiles()).toList().isEmpty());
    }

    /**
     * This test fails under Windows because creating file with this invalid file name fails first
     * @param tempDir
     * @throws Exception
     */
    @DisabledOnOs(OS.WINDOWS)
    @Test
    void testThatIncompleteCDocFilesAreRemoved(@TempDir Path tempDir) throws Exception {
        PublicKey publicKey = createPublicKey();
        UUID uuid = UUID.randomUUID();
        String payloadFileName = "-payload:" + uuid + ".txt"; //invalid
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();


        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        var encKM = EncryptionKeyMaterial
            .fromPublicKey(publicKey, bobKeyLabelParams);

        File cdocFile = tempDir.resolve("incomplete.cdoc2").toFile();

        Files.createFile(cdocFile.toPath());
        assertTrue(cdocFile.exists());

        String overwrite = System.getProperty(OVERWRITE_PROPERTY);
        System.setProperty(OVERWRITE_PROPERTY, "true");
        try {
            assertThrows(
                Exception.class,
                () -> EnvelopeTestUtils.createContainerUsingCDocBuilder(cdocFile, payloadFile,
                    payloadData.getBytes(StandardCharsets.UTF_8), encKM, null, null)
            );

            assertFalse(cdocFile.exists());
        } finally {
            if (overwrite != null) {
                System.setProperty(OVERWRITE_PROPERTY, overwrite);
            }
        }
    }

    @Disabled("Needs real id-code") // replace idCode with id code present in SK LDAP
    @Test
    void testCdocBuilder(@TempDir Path tempDir) throws Exception {
        //https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters
        // #test-accounts-for-automated-testing
        // fails as this is test id-code for Smart-ID and doesn't exist in SK LDAP
        String idCode = "30303039914"; // replace with real id code present in SK LDAP

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();
        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        File cdocFile = tempDir.resolve("testCdocBuilder.cdoc2").toFile();

        List<EncryptionKeyMaterial> encKeyMaterial = new EstEncKeyMaterialBuilder()
            // will download recipient certificate and add public key based recipient
            .fromCertDirectory(new String[]{idCode})
            // will create authentication based recipient
            .forAuthMeans(new String[]{idCode})
            .build();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        List<File> files = new LinkedList<>();
        files.add(payloadFile);

        CDocBuilder builder = new CDocBuilder()
            .withPayloadFiles(files)
            .withRecipients(encKeyMaterial)
            .withServices(getMockCdoc2Services());

        builder.buildToFile(cdocFile);

        List<Recipient> recipients = Envelope.parseHeader(Files.newInputStream(cdocFile.toPath()));

        assertTrue(recipients.size() == 2);

        String label0 = recipients.get(0).getRecipientKeyLabel();
        assertTrue(label0.contains(idCode));
        assertTrue(label0.contains("ID-card"));

        assertEquals("etsi/PNOEE-" + idCode, recipients.get(1).getRecipientId());

        String label1 = recipients.get(1).getRecipientKeyLabel().toUpperCase();
        assertTrue(label1.contains("TYPE=AUTH"));
        assertTrue(label1.contains(idCode));

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

        SecretKey preSharedKey = createSecretKey();
        String keyLabel = "testTarWithExtraData";

        EncryptionKeyMaterial encryptionKeyMaterial
            = EncryptionKeyMaterial.fromSecret(preSharedKey, keyLabel);


        byte[] cdocBytes = EnvelopeTestUtils.createContainer(
            payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8),
            encryptionKeyMaterial,
            null,
            null
        );

        assertTrue(cdocBytes.length > 0);

        log.debug("cdoc length: {}", cdocBytes.length);

        byte[] tarWithExtraDataPayload = EnvelopeTestUtils.createTarWithExtraData();
        byte[] newCdocBytes = EnvelopeTestUtils.replacePayload(
            cdocBytes,
            preSharedKey,
            encryptionKeyMaterial.getLabel(),
            tarWithExtraDataPayload
        );

        log.debug("CDOC size {}", newCdocBytes.length);

        CountingInputStream countingInputStream = new CountingInputStream(new ByteArrayInputStream(newCdocBytes));

        IOException ioex = assertThrows(IOException.class, () -> Envelope.list(
            countingInputStream,
            DecryptionKeyMaterial.fromSecretKey(preSharedKey, keyLabel), null
        ));

        assertEquals("Unexpected data after tar", ioex.getMessage());

        assertEquals(newCdocBytes.length, countingInputStream.getByteCount());

        // Although IOException is thrown, it should not be reported if MAC is wrong
        // MAC check exception is thrown instead of "Unexpected data after tar"
        byte[] wrongPoly1305MacCdoc = Arrays.copyOf(newCdocBytes, newCdocBytes.length);
        wrongPoly1305MacCdoc[wrongPoly1305MacCdoc.length - 1] = (byte) 0xff; //corrupt MAC

        CountingInputStream wrongMacIs =
            new CountingInputStream(new ByteArrayInputStream(wrongPoly1305MacCdoc));

        IOException ex = assertThrows(IOException.class, () -> Envelope.list(
            wrongMacIs,
            DecryptionKeyMaterial.fromSecretKey(preSharedKey, keyLabel), null
        ));

        assertInstanceOf(AEADBadTagException.class, ex.getCause());
        assertEquals("mac check in ChaCha20Poly1305 failed", ex.getCause().getMessage());

        assertEquals(newCdocBytes.length, wrongMacIs.getByteCount());
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

        SecretKey preSharedKey = createSecretKey();

        String keyLabel = "testTarWithExtraData";

        EncryptionKeyMaterial ekm = EncryptionKeyMaterial.fromSecret(preSharedKey, keyLabel);

        byte[] cdocBytes = EnvelopeTestUtils.createContainer(
            payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8),
            ekm,
            null,
            null
        );

        assertTrue(cdocBytes.length > 0);

        log.debug("original cdoc length: {}", cdocBytes.length);

        byte[] newCdocBytes =
            EnvelopeTestUtils.replacePayload(cdocBytes, preSharedKey, ekm.getLabel(), tarWithIllegalFileTypeBytes);
        log.debug("replaced payload");

        log.debug("modified CDOC size {}", newCdocBytes.length);

        CountingInputStream countingInputStream = new CountingInputStream(new ByteArrayInputStream(newCdocBytes));

        IOException ioex = assertThrows(IOException.class, () -> Envelope.decrypt(
            countingInputStream,
            DecryptionKeyMaterial.fromSecretKey(preSharedKey, keyLabel), outDir, null, null
        ));

        assertEquals("Tar entry with illegal type found", ioex.getMessage());

        // all cdoc bytes were processed and Poly1305 MAC checked
        assertEquals(newCdocBytes.length, countingInputStream.getByteCount());

        //extracted files were deleted
        assertTrue(Arrays.stream(outDir.toFile().listFiles()).toList().isEmpty());

        // MAC check exception is thrown instead of "Unexpected data after tar"
        byte[] wrongPoly1305MacCdoc = Arrays.copyOf(newCdocBytes, newCdocBytes.length);
        wrongPoly1305MacCdoc[wrongPoly1305MacCdoc.length - 1] = (byte) 0xff; //corrupt MAC

        CountingInputStream wrongMacIs =
            new CountingInputStream(new ByteArrayInputStream(wrongPoly1305MacCdoc));

        IOException ex = assertThrows(IOException.class, () -> Envelope.decrypt(
            wrongMacIs,
            DecryptionKeyMaterial.fromSecretKey(preSharedKey, keyLabel), outDir, null, null
        ));

        assertInstanceOf(AEADBadTagException.class, ex.getCause());
        assertEquals("mac check in ChaCha20Poly1305 failed", ex.getCause().getMessage());

        assertEquals(newCdocBytes.length, wrongMacIs.getByteCount());

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

        KeyPair bobKeyPair = createKeyPair();

        ECPublicKey bobPubKey = (ECPublicKey) bobKeyPair.getPublic();

        // Code to find the limit of max header
        int singleKeyLen = Envelope.prepare(
                List.of(EncryptionKeyMaterial
                    .fromPublicKey(bobPubKey, bobKeyLabelParams)),
                null, null)
            .serializeHeader().length;
        int twoKeyLen = Envelope.prepare(
                List.of(
                    EncryptionKeyMaterial
                        .fromPublicKey(bobPubKey, bobKeyLabelParams),
                    EncryptionKeyMaterial
                        .fromPublicKey(
                            ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1).getPublic(),
                            getPublicKeyLabelParams()
                        )
                ), null, null
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
            .map(entry -> EncryptionKeyMaterial
                .fromPublicKey(entry.getKey(), bobKeyLabelParams))
            .collect(Collectors.toList()); //mutable list

        Instant end = Instant.now();
        log.debug("Generated {} EC keys in {}s", keyLabelMap.size(), end.getEpochSecond() - start.getEpochSecond());

        Instant prepareStart = Instant.now();
        Envelope senderEnvelope = Envelope.prepare(recipients, null, null);
        Instant prepareEnd = Instant.now();
        log.debug("Prepared {} EC sender keys in {}s", keyLabelMap.size(),
            prepareEnd.getEpochSecond() - prepareStart.getEpochSecond());

        Instant serializeStart = Instant.now();
        byte[] headerBuf = senderEnvelope.serializeHeader();
        Instant serializeEnd = Instant.now();
        log.debug("Recipients: {} header size: {}B in {}s", keyLabelMap.size(), headerBuf.length,
            serializeEnd.getEpochSecond() - serializeStart.getEpochSecond());

        //  test that serialization fails for oversize header
        recipients.add(
            EncryptionKeyMaterial
                .fromPublicKey(
                    ECKeys.generateEcKeyPair(ECKeys.SECP_384_R_1).getPublic(),
                    getPublicKeyLabelParams()
                )
        );

        Envelope prepare = Envelope.prepare(recipients, null, null);
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
                    outDir, null, null);

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
    @Disabled("requires 16GB of free disk space on /tmp and takes about ~8min to run")
    void test8GBPlusFileContainer(@TempDir Path tempDir) throws Exception {

        // since generated file is random, zlib can't compress it effectively and
        // created cdoc might be bigger than original file
        long sixteenGB = (16L + 1L) * 1024L * 1024L * 1024L;
        if (tempDir.toFile().getUsableSpace() < sixteenGB) {
            log.error("Need {} B of free space, but only {} B available", sixteenGB, tempDir.toFile().getUsableSpace());
            fail("Not enough free disk space at " + tempDir);
        }

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        Files.writeString(payloadFile.toPath(), payloadData);

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
        byte[] secret = new byte[Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES];
        Crypto.getSecureRandom().nextBytes(secret);
        SecretKey key = new SecretKeySpec(secret, "");

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromSecret(key, label)),
            null, null
        );

        File bigDotCdoc = outDir.resolve("big.cdoc2").toFile();

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
                Envelope.list(cdoc, DecryptionKeyMaterial.fromSecretKey(key, label), null);

            entryList.forEach(entry -> log.debug("{} {}", entry.getName(), entry.getSize()));

            assertEquals(2, entryList.size());
            assertEquals("bigFile", entryList.get(1).getName());
            assertEquals(mbWanted * oneMb.length, entryList.get(1).getSize());
        }
        log.debug("Done.");
    }

    private void setUpKeyLabelFormat(boolean isFormatted) {
        Properties props = System.getProperties();
        props.setProperty(
            "ee.cyber.cdoc2.key-label.machine-readable-format.enabled",
            String.valueOf(isFormatted)
        );
    }

    private void testKeySharesSerialization(
        Path tempDir,
        AuthenticationIdentifier authIdentifier,
        AuthenticationIdentifier.AuthenticationType authType,
        String idCode
    ) throws Exception {
        setupKeyShareClientMocks();

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData.getBytes(StandardCharsets.UTF_8));
        }

        Envelope envelope = Envelope.prepare(
            List.of(EncryptionKeyMaterial.fromAuthMeans(
                authIdentifier, createKeyLabelParams(idCode, authType))
            ),
            null, sharesClientFactory
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

        assertEquals(recipients_KeySharesCapsule, recipient.capsuleType());

        KeySharesCapsule keySharesCapsule = (KeySharesCapsule) recipient.capsule(new KeySharesCapsule());
        assertNotNull(keySharesCapsule);

        ByteBuffer saltBuf = keySharesCapsule.saltAsByteBuffer();
        assertNotNull(saltBuf);
    }

    private void verifyMockedKeyShareClients() throws Exception {
        verify(mockKeySharesClient1).storeKeyShare(keyShareCaptor1.capture());
        verify(mockKeySharesClient2).storeKeyShare(keyShareCaptor2.capture());

        KeyShare keyShare1 = keyShareCaptor1.getValue();
        KeyShare keyShare2 = keyShareCaptor2.getValue();

        NonceResponse nonce1 = new NonceResponse().nonce("nonce01nonce01");
        NonceResponse nonce2 = new NonceResponse().nonce("nonce02nonce02");

        when(mockKeySharesClient1.getKeyShare(any(), any(), any())).thenReturn(Optional.of(keyShare1));
        when(mockKeySharesClient2.getKeyShare(any(), any(), any())).thenReturn(Optional.of(keyShare2));

        when(mockKeySharesClient1.createKeyShareNonce(any())).thenReturn(nonce1);
        when(mockKeySharesClient2.createKeyShareNonce(any())).thenReturn(nonce2);
    }

}
