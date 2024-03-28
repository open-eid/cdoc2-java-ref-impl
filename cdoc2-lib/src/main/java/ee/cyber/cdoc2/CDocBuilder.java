package ee.cyber.cdoc2;

import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.container.Envelope;
import ee.cyber.cdoc2.crypto.Crypto;
import ee.cyber.cdoc2.crypto.ECKeys;
import ee.cyber.cdoc2.crypto.EllipticCurve;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyAlgorithm;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.PublicKeyEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.SecretEncryptionKeyMaterial;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;


/**
 * CDocBuilder for building CDOCs using EC (secp384r1) or RSA public keys or symmetric key.
 */
public class CDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(CDocBuilder.class);

    private List<File> payloadFiles;
    private final List<EncryptionKeyMaterial> recipients = new LinkedList<>();
    private Properties serverProperties;

    public CDocBuilder withPayloadFiles(List<File> files) {
        this.payloadFiles = files;
        return this;
    }

    public CDocBuilder withRecipient(EncryptionKeyMaterial recipientEncKM) {
        this.recipients.add(recipientEncKM);
        return this;
    }

    public CDocBuilder withRecipients(List<EncryptionKeyMaterial> recipientsEncKM) {
        this.recipients.addAll(recipientsEncKM);
        return this;
    }

    public CDocBuilder withServerProperties(Properties p) {
        this.serverProperties = p;
        return this;
    }

    public void buildToFile(File outputCDocFile) throws CDocException, IOException, CDocValidationException {
        if (outputCDocFile == null) {
            throw new CDocValidationException("Must provide CDOC output filename ");
        }

        ensureFileCanBeCreatedInOutputDir(outputCDocFile);
        OpenOption openOption = getOpenOption();

        try (OutputStream outputStream = Files.newOutputStream(outputCDocFile.toPath(), openOption)) {
            buildToOutputStreamFromFiles(outputStream);
        } catch (Exception ex) {
            handleFileEncryptionError(ex, outputCDocFile);
            throw ex;
        }
    }

    private void buildToOutputStreamFromFiles(OutputStream outputStream)
        throws CDocException, CDocValidationException, IOException {
        validate();

        try {
            Envelope envelope = prepareEnvelope();
            envelope.encrypt(this.payloadFiles, outputStream);
        } catch (GeneralSecurityException ex) {
            throw new CDocException(ex);
        }
    }

    private void ensureFileCanBeCreatedInOutputDir(File outputCDocFile) throws FileAlreadyExistsException {
        if (!CDocConfiguration.isOverWriteAllowed() && Files.exists(outputCDocFile.toPath())) {
            log.info("File {} already exists.", outputCDocFile.toPath().toAbsolutePath());
            throw new FileAlreadyExistsException(outputCDocFile.toPath().toAbsolutePath().toString());
        }
    }

    private OpenOption getOpenOption() {
        return (CDocConfiguration.isOverWriteAllowed())
            ? StandardOpenOption.CREATE
            : StandardOpenOption.CREATE_NEW;
    }

    private Envelope prepareEnvelope()
        throws ExtApiException, GeneralSecurityException, IOException {
        if (serverProperties == null) {
            return Envelope.prepare(recipients, null);
        } else {
            // for encryption, do not init mTLS client as this might require smart-card
            return Envelope.prepare(recipients, KeyCapsuleClientImpl.create(serverProperties, false));
        }
    }

    private void handleFileEncryptionError(Exception ex, File outputCDocFile) {
        log.info("Failed to create {}. Exception: {}", outputCDocFile, ex.getMessage());

        try {
            boolean deleted = Files.deleteIfExists(outputCDocFile.toPath());
            if (deleted) {
                log.info("Deleted {}", outputCDocFile);
            }

        } catch (IOException ioException) {
            log.error("Error when deleting {} {}", outputCDocFile, ioException);
        }
    }

    public void validate() throws CDocValidationException {
        validateRecipients();
        validatePayloadFiles();
    }

    void validateRecipients() throws CDocValidationException {
        if (this.recipients.isEmpty()) {
            throw new CDocValidationException("Must provide at least one recipient");
        }

        for (EncryptionKeyMaterial keyMaterial : this.recipients) {
            validateEncryptionKey(keyMaterial);
        }
    }

    private void validateEncryptionKey(EncryptionKeyMaterial keyMaterial)
        throws CDocValidationException {

        if (EncryptionKeyOrigin.PASSWORD.equals(keyMaterial.getKeyOrigin())) {
            // no encryption key at this step
            return;
        }

        if (keyMaterial instanceof PublicKeyEncryptionKeyMaterial publicKeyMaterial) {
            validatePublicKeyMaterial(publicKeyMaterial);
        } else if (keyMaterial instanceof SecretEncryptionKeyMaterial secretKeyMaterial) {
            SecretKey secretKey = secretKeyMaterial.getSecretKey();
            if ((secretKey.getEncoded() == null)
                || (secretKey.getEncoded().length < Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES)) {
                throw new CDocValidationException("Too short key for label: " + secretKeyMaterial.getLabel());
            }
        } else {
            String errorMsg = "Unsupported key " + keyMaterial.getLabel();
            log.error(errorMsg);
            throw new CDocValidationException(errorMsg);
        }
    }

    private void validatePublicKeyMaterial(PublicKeyEncryptionKeyMaterial publicKeyMaterial)
        throws CDocValidationException {

        PublicKey publicKey = publicKeyMaterial.getPublicKey();
        if (KeyAlgorithm.isEcKeysAlgorithm(publicKey.getAlgorithm())) {
            validateEcPublicKey((ECPublicKey) publicKey);
        } else if (KeyAlgorithm.isRsaKeysAlgorithm(publicKey.getAlgorithm())) {
            validateRsaPublicKey((RSAPublicKey) publicKey);
        } else {
            String errorMsg = ("Unsupported public key algorithm "
                + publicKey.getAlgorithm() + "for key " + publicKeyMaterial.getLabel());
            log.error(errorMsg);
            throw new CDocValidationException(errorMsg);
        }
    }

    /**
     * All RSA keys are considered good. Shorter will fail during encryption as OAEP takes some
     * space.
     */
    private void validateRsaPublicKey(RSAPublicKey rsaPublicKey) throws CDocValidationException {
        // no good way to check RSA key length as BigInteger can start with 00 and that changes bit-length
        if (rsaPublicKey.getModulus().bitLength() <= 512) {
            throw new CDocValidationException("RSA key does not meet length requirements");
        }
    }

    private void validateEcPublicKey(ECPublicKey ecPubKey) throws CDocValidationException {
        String encoded = Base64.getEncoder().encodeToString(ecPubKey.getEncoded());
        try {
            EllipticCurve curve = retrieveEllipticCurve(ecPubKey, encoded);

            if (!curve.isValidKey(ecPubKey)) {
                log.error("EC pub key is not valid for curve {}. EC public key={}",
                    curve.getName(), encoded);
                throw new CDocValidationException("Recipient key not valid");
            }
        } catch (GeneralSecurityException gse) {
            throw new CDocValidationException("Invalid recipient " + encoded, gse);
        }
    }

    private EllipticCurve retrieveEllipticCurve(
        ECPublicKey recipientPubKey,
        String encodedPublicKey
    ) throws GeneralSecurityException, CDocValidationException {
        String curveOid = ECKeys.getCurveOid(recipientPubKey);

        try {
            return EllipticCurve.forOid(curveOid);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            log.error("EC pub key curve ({}) is not supported. EC public key={}",
                curveOid, encodedPublicKey);
            throw new CDocValidationException("Invalid recipient key with key " + curveOid);
        }
    }

    void validatePayloadFiles() throws CDocValidationException {
        if (payloadFiles == null || payloadFiles.isEmpty()) {
            log.error("Must contain at least one payload file");
            throw new CDocValidationException("Must contain at least one payload file");
        }

        for (File file: payloadFiles) {
            if (!(file.exists() && file.isFile() && file.canRead())) {
                log.error("Invalid payload file {}", file);
                throw new CDocValidationException("Invalid payload file " + file);
            }
        }
    }
}
