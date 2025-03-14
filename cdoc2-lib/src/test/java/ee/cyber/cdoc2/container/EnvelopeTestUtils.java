package ee.cyber.cdoc2.container;

import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.PasswordDecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.decrypt.SecretDecryptionKeyMaterial;
import ee.cyber.cdoc2.CDocBuilder;
import ee.cyber.cdoc2.exceptions.CDocException;
import ee.cyber.cdoc2.exceptions.CDocValidationException;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeyCapsuleClient;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.crypto.ChaChaCipher;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.fbs.header.FMKEncryptionMethod;
import ee.cyber.cdoc2.fbs.header.Header;
import ee.cyber.cdoc2.fbs.header.RecipientRecord;
import ee.cyber.cdoc2.fbs.recipients.SymmetricKeyCapsule;
import ee.cyber.cdoc2.services.Services;
import ee.cyber.cdoc2.services.ServicesBuilder;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.UUID;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.isKeyLabelMachineReadableFormatEnabled;
import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.createSemanticsIdentifier;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createKeySharesKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createPublicKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSymmetricKeyLabelParams;
import static ee.cyber.cdoc2.fbs.header.Capsule.recipients_SymmetricKeyCapsule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


public final class EnvelopeTestUtils {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeTestUtils.class);

    private EnvelopeTestUtils() {
    }

    /**
     * Replace payload inside cdoc2 container. Limitation is that container must be created with SecretKey and Label
     * @param origCdocBytes cdoc2 container
     * @param preSharedKey pre-shared key
     * @param keyLabel key label
     * @param newCdocPayload payload from origCdocBytes will be replaced with encrypted newCdocPayload
     * @return new cdoc2 container where original payload was replaced with newCdocPayload
     * @throws IOException if an I/O error has occurred
     * @throws CDocParseException
     */
    static byte[] replacePayload(
        byte[] origCdocBytes,
        SecretKey preSharedKey,
        String keyLabel,
        byte[] newCdocPayload
    ) throws IOException, CDocParseException, GeneralSecurityException {
        byte[] headerBytes = Envelope.readFBSHeader(new ByteArrayInputStream(origCdocBytes));
        Header header = Envelope.deserializeFBSHeader(headerBytes);

        int hmacStart = Envelope.PRELUDE.length
            + Byte.BYTES //version 0x02
            + Integer.BYTES //header length field
            + headerBytes.length;
        byte[] hmacBytes = Arrays.copyOfRange(origCdocBytes, hmacStart, hmacStart + Crypto.HHK_LEN_BYTES);
        assertEquals(Crypto.HHK_LEN_BYTES, hmacBytes.length);

        RecipientRecord recipient = header.recipients(0);
        ByteBuffer encFmkBuf = recipient.encryptedFmkAsByteBuffer();
        byte[] encFmk = Arrays.copyOfRange(encFmkBuf.array(), encFmkBuf.position(), encFmkBuf.limit());

        if (recipient.capsuleType() != recipients_SymmetricKeyCapsule) {
            throw new IllegalArgumentException("Expected CDOC2 container to contain SymmetricKeyCapsule");
        }

        SymmetricKeyCapsule symmetricKeyCapsule = (SymmetricKeyCapsule) recipient.capsule(new SymmetricKeyCapsule());
        ByteBuffer saltBuf = symmetricKeyCapsule.saltAsByteBuffer();
        byte[] salt = Arrays.copyOfRange(saltBuf.array(), saltBuf.position(), saltBuf.limit());

        SecretKey kek = Crypto.deriveKeyEncryptionKey(keyLabel,
            preSharedKey,
            salt,
            FMKEncryptionMethod.name(recipient.fmkEncryptionMethod()));
        byte[] fmk = Crypto.xor(kek.getEncoded(), encFmk);

        SecretKey cek = Crypto.deriveContentEncryptionKey(fmk);

        byte[] encryptedTarWithExtraData = encryptPayload(cek,
            Envelope.getAdditionalData(headerBytes, hmacBytes),
            newCdocPayload);

        //replace original cdoc payload part with new custom tar
        byte[] newCdocBytes = new byte[hmacStart + Crypto.HHK_LEN_BYTES + encryptedTarWithExtraData.length];

        System.arraycopy(origCdocBytes, 0, newCdocBytes, 0,
            hmacStart + Crypto.HHK_LEN_BYTES);
        System.arraycopy(encryptedTarWithExtraData, 0,
            newCdocBytes, hmacStart + Crypto.HHK_LEN_BYTES, encryptedTarWithExtraData.length);
        return newCdocBytes;
    }

    static byte[] encryptPayload(SecretKey cek, byte[] aad, byte[] payloadBytes)
        throws IOException, GeneralSecurityException {

        ByteArrayOutputStream destChaChaStream = new ByteArrayOutputStream();
        try (CipherOutputStream cipherOutputStream = ChaChaCipher.initChaChaOutputStream(destChaChaStream, cek, aad)) {
            cipherOutputStream.write(payloadBytes);
            cipherOutputStream.flush();
        }
        return destChaChaStream.toByteArray();
    }

    static byte[] createTarWithExtraData() throws IOException {
        // https://superuser.com/questions/448623/how-to-get-an-empty-tar-archive
        byte[] tarBytes = new byte[1024 + 512]; //1024 bytes of 0x00 is valid tar
        // + 512 bytes for extra data, that will not be processed by tar
        String extraData = "testTarWithExtraData";
        System.arraycopy(extraData.getBytes(StandardCharsets.UTF_8), 0, tarBytes, 1024,
            extraData.getBytes(StandardCharsets.UTF_8).length);

        // generate random bytes so that compression ratio would not be over 10.0
        // copy tar to begging of it
        byte[] randomBytes  = new byte[64 * 1024];
        new Random().nextBytes(randomBytes);

        System.arraycopy(tarBytes, 0, randomBytes, 0,
            tarBytes.length);

        ByteArrayOutputStream destTarZlib = new ByteArrayOutputStream();

        InputStream tarInputStream = new ByteArrayInputStream(randomBytes);
        DeflateParameters deflateParameters = new DeflateParameters();
        deflateParameters.setCompressionLevel(9);

        try (DeflateCompressorOutputStream zOs =
                 new DeflateCompressorOutputStream(new BufferedOutputStream(destTarZlib), deflateParameters)) {
            long copied = tarInputStream.transferTo(zOs);
            log.debug("Copied {}B from tar to deflate", copied);
        }

        log.debug("Compressed {} into {}", randomBytes.length, destTarZlib.size());

        return destTarZlib.toByteArray();
    }

    static byte[] createTarWithIllegalFileType() throws IOException {

        String validFileName = "validFile";
        byte[] data = new byte[10 * 1024];

        ByteArrayOutputStream dest = new ByteArrayOutputStream();

        try (TarArchiveOutputStream tarOs = Tar.createPosixTarZArchiveOutputStream(dest)) {

            TarArchiveEntry tarEntry1 = new TarArchiveEntry(validFileName);
            tarEntry1.setSize(data.length);
            tarOs.putArchiveEntry(tarEntry1);
            new Random().nextBytes(data);
            tarOs.write(data);
            tarOs.closeArchiveEntry();

            TarArchiveEntry tarEntry2 = new TarArchiveEntry("nonRegularFile/", TarConstants.LF_LINK);
            tarOs.putArchiveEntry(tarEntry2);
            tarOs.closeArchiveEntry();

            TarArchiveEntry tarEntry3 = new TarArchiveEntry(validFileName + ".2");
            tarEntry3.setSize(data.length);
            tarOs.putArchiveEntry(tarEntry3);
            new Random().nextBytes(data);
            tarOs.write(data);
            tarOs.closeArchiveEntry();
        }

        return dest.toByteArray();
    }

    /**
     * Creates payloadFile, adds payloadData to payloadFile and creates encrypted container for recipientPubKey
     * @param payloadFile input payload file to be created and added to container
     * @param payloadData data to be written to payloadFile
     * @param encKeyMaterial encryption key material (either public key or symmetric key)
     * @param additionalFiles optional additional file to add
     * @param capsuleClient capsule client
     * @return created container as byte[]
     * @throws IOException if IOException happens
     * @throws GeneralSecurityException if GeneralSecurityException happens
     */
    public static byte[] createContainer(
        File payloadFile,
        byte[] payloadData,
        EncryptionKeyMaterial encKeyMaterial,
        @Nullable List<File> additionalFiles,
        @Nullable KeyCapsuleClient capsuleClient
    ) throws IOException, GeneralSecurityException, ExtApiException {

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData);
        }

        List<File> files = new LinkedList<>();
        files.add(payloadFile);
        if (additionalFiles != null) {
            files.addAll(additionalFiles);
        }

        byte[] cdocContainerBytes;
        Envelope senderEnvelope = Envelope.prepare(
            List.of(encKeyMaterial), capsuleClient, null
        );
        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(files, dst);
            cdocContainerBytes = dst.toByteArray();
        }
        assertNotNull(cdocContainerBytes);
        assertTrue(cdocContainerBytes.length > 0);
        return cdocContainerBytes;
    }

    public static byte[] createContainerWithKeyShares(
        File payloadFile,
        byte[] payloadData,
        AuthenticationIdentifier authIdentifier,
        KeySharesClientFactory sharesClientFactory
    ) throws IOException, GeneralSecurityException, ExtApiException {

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData);
        }

        List<File> files = new LinkedList<>();
        files.add(payloadFile);

        KeyLabelParams keyLabelParams = createKeyLabelParams(authIdentifier.getIdCode(), authIdentifier.getAuthType());

        EncryptionKeyMaterial encKeyMaterial
            = EncryptionKeyMaterial.fromAuthMeans(authIdentifier, keyLabelParams);

        byte[] cdocContainerBytes;
        Envelope senderEnvelope = Envelope.prepare(
            List.of(encKeyMaterial), null, sharesClientFactory
        );
        try (ByteArrayOutputStream dst = new ByteArrayOutputStream()) {
            senderEnvelope.encrypt(files, dst);
            cdocContainerBytes = dst.toByteArray();
        }
        assertNotNull(cdocContainerBytes);
        assertTrue(cdocContainerBytes.length > 0);
        return cdocContainerBytes;
    }

    /**
     * Creates CDOC2 container in tempDir and encrypts/decrypts it with keyPair. If
     * capsulesClient is provided, then test server scenarios
     */
    public static void testContainer(
        Path tempDir,
        DecryptionKeyMaterial keyMaterial,
        String keyLabel,
        @Nullable KeyCapsuleClient capsulesClient
    ) throws Exception {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        EncryptionKeyMaterial encKeyMaterial =
            (keyMaterial instanceof KeyPairDecryptionKeyMaterial keyPairKeyMaterial)
                ? createEncryptionKeyMaterialForPublicKey(
                    keyPairKeyMaterial.getKeyPair().getPublic(),
                    keyLabel)
                : createEncryptionKeyMaterialForSymmetricKey(keyMaterial, keyLabel);

        byte[] cdocContainerBytes = createContainer(payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8), encKeyMaterial, null,
            capsulesClient);

        assertTrue(cdocContainerBytes.length > 0);

        ServicesBuilder servicesBuilder = new ServicesBuilder();

        if (capsulesClient != null) {
            servicesBuilder.register(KeyCapsuleClientFactory.class, getCapsulesClientFactory(capsulesClient), null);
        }

        checkContainerDecrypt(cdocContainerBytes, outDir, keyMaterial,
            List.of(payloadFileName), payloadFileName, payloadData, servicesBuilder.build());
    }

    /**
     * Creates CDOC2 container in tempDir and encrypts/decrypts it with key shares.
     */
    public static DecryptionData testContainerWithKeyShares(
        Path tempDir,
        AuthenticationIdentifier encryptAuthIdentifier,
        AuthenticationIdentifier decryptAuthIdentifier,
        KeySharesClientFactory sharesClientFactory
    ) throws Exception {

        UUID uuid = UUID.randomUUID();
        String payloadFileName = "payload-" + uuid + ".txt";
        String payloadData = "payload-" + uuid;
        File payloadFile = tempDir.resolve(payloadFileName).toFile();

        Path outDir = tempDir.resolve("testContainer-" + uuid);
        Files.createDirectories(outDir);

        byte[] cdocContainerBytes = createContainerWithKeyShares(
            payloadFile,
            payloadData.getBytes(StandardCharsets.UTF_8),
            encryptAuthIdentifier,
            sharesClientFactory
        );

        assertTrue(cdocContainerBytes.length > 0);

        return new DecryptionData(
            cdocContainerBytes,
            outDir,
            DecryptionKeyMaterial.fromAuthMeans(decryptAuthIdentifier),
            payloadFileName,
            payloadData
        );
    }

    private static EncryptionKeyMaterial createEncryptionKeyMaterialForPublicKey(
        PublicKey publicKey,
        String label
    ) {
        return EncryptionKeyMaterial.fromPublicKey(publicKey, KeyLabelTools.createPublicKeyLabelParams(label, null));
    }

    private static EncryptionKeyMaterial createEncryptionKeyMaterialForSymmetricKey(
        DecryptionKeyMaterial keyMaterial, String keyLabel
    ) {
        if (keyMaterial instanceof PasswordDecryptionKeyMaterial passwordKeyMaterial) {
            return EncryptionKeyMaterial.fromPassword(
                passwordKeyMaterial.getPassword(), keyLabel
            );
        } else if (keyMaterial instanceof SecretDecryptionKeyMaterial secretKeyMaterial) {
            return createEncryptionKeyMaterialAccordingToKeyLabelFormat(
                secretKeyMaterial.getSecretKey(), keyLabel
            );
        } else {
            throw new RuntimeException();
        }
    }

    public static void checkContainerDecrypt(
        byte[] cdocBytes,
        Path outDir,
        DecryptionKeyMaterial keyMaterial,
        List<String> expectedFilesExtracted,
        String payloadFileName,
        String expectedPayloadData,
        Services services
    )  throws Exception {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(cdocBytes)) {
            List<String> filesExtracted = Envelope.decrypt(bis, keyMaterial, outDir, services);

            assertEquals(expectedFilesExtracted, filesExtracted);
            Path payloadPath = Path.of(outDir.toAbsolutePath().toString(), payloadFileName);

            assertEquals(expectedPayloadData, Files.readString(payloadPath));
        }
    }

    public static void reEncryptContainer(
        InputStream cdocIs,
        DecryptionKeyMaterial decryptionKeyMaterial,
        OutputStream destCdoc,
        EncryptionKeyMaterial encryptionKeyMaterial,
        @Nullable Path destDir,
        @Nullable KeyCapsuleClient capsuleClient
    ) throws Exception {

        ServicesBuilder sb = new ServicesBuilder();
        if (capsuleClient != null) {
            sb.register(KeyCapsuleClientFactory.class, getCapsulesClientFactory(capsuleClient), null);
        }
        Envelope.reEncrypt(cdocIs, decryptionKeyMaterial, destCdoc, encryptionKeyMaterial,
            destDir, sb.build());
    }

    public static void createContainerUsingCDocBuilder(
        File cdocFileToCreate,
        File payloadFile,
        byte[] payloadData,
        EncryptionKeyMaterial encKeyMaterial,
        @Nullable List<File> additionalFiles,
        Services services
    ) throws IOException, CDocException, CDocValidationException, ConfigurationLoadingException {

        try (FileOutputStream payloadFos = new FileOutputStream(payloadFile)) {
            payloadFos.write(payloadData);
        }

        List<File> files = new LinkedList<>();
        files.add(payloadFile);
        if (additionalFiles != null) {
            files.addAll(additionalFiles);
        }

        CDocBuilder builder = new CDocBuilder()
            .withPayloadFiles(files)
            .withRecipients(List.of(encKeyMaterial));
            //.withServerProperties(serverProperties);

        builder.buildToFile(cdocFileToCreate);
    }

    public static KeyLabelParams getPublicKeyLabelParams() {
        return getPublicKeyLabelParams(null);
    }

    public static KeyLabelParams getPublicKeyLabelParams(@Nullable String label) {
        return createPublicKeyLabelParams(label, null);
    }

    public static KeyCapsuleClientFactory getCapsulesClientFactory(KeyCapsuleClient capsulesClient) {
        return (capsulesClient == null) ? null : serverId -> {
            Objects.requireNonNull(serverId);
            if (serverId.equals(capsulesClient.getServerIdentifier())) {
                return capsulesClient;
            }

            log.warn("No KeyCapsulesClient for {}", serverId);
            return null;
        };
    }

    private static EncryptionKeyMaterial createEncryptionKeyMaterialAccordingToKeyLabelFormat(
        SecretKey secretKey,
        String keyLabel
    ) {
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
                EncryptionKeyOrigin.SECRET, keyLabel
            );
            return EncryptionKeyMaterial.fromSecret(
                secretKey, keyLabelParams
            );
        } else {
            return EncryptionKeyMaterial.fromSecret(
                secretKey, keyLabel
            );
        }
    }

    record DecryptionData(
        byte[] cdocContainerBytes,
        Path outDir,
        DecryptionKeyMaterial decryptionKeyMaterial,
        String payloadFileName,
        String payloadData
    ) {
    }

    static KeyLabelParams createKeyLabelParams(
        String idCode,
        AuthenticationIdentifier.AuthenticationType type
    ) {
        SemanticsIdentifier semanticsIdentifier = createSemanticsIdentifier(idCode);
        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier
            .forKeyShares(semanticsIdentifier, type);

        return createKeySharesKeyLabelParams(authIdentifier.getEtsiIdentifier());
    }

}
