package ee.cyber.cdoc20;

import ee.cyber.cdoc20.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

import ee.cyber.cdoc20.crypto.keymaterial.EncryptionKeyMaterial;
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
 * CDocBuilder for building CDOCs using EC (secp384r1) or RSA public keys.
 */
public class CDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(CDocBuilder.class);

    private List<File> payloadFiles;
    private List<EncryptionKeyMaterial> recipients = new LinkedList<>();
    private Properties serverProperties;

    public CDocBuilder withPayloadFiles(List<File> files) {
        this.payloadFiles = files;
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

        OpenOption openOption = (CDocConfiguration.isOverWriteAllowed())
                ? StandardOpenOption.CREATE
                : StandardOpenOption.CREATE_NEW;
        if (!CDocConfiguration.isOverWriteAllowed() && Files.exists(outputCDocFile.toPath())) {
            log.info("File {} already exists.", outputCDocFile.toPath().toAbsolutePath());
            throw new FileAlreadyExistsException(outputCDocFile.toPath().toAbsolutePath().toString());
        }

        try (OutputStream outputStream = Files.newOutputStream(outputCDocFile.toPath(), openOption)) {
            buildToOutputStream(outputStream);
        } catch (Exception ex) {
            log.info("Failed to create {}. Exception: {}", outputCDocFile, ex.getMessage());
            try {
                boolean deleted = Files.deleteIfExists(outputCDocFile.toPath());
                if (deleted) {
                    log.info("Deleted {}", outputCDocFile);
                }

            } catch (IOException ioException) {
                log.error("Error when deleting {} {}", outputCDocFile, ioException);
            }
            throw ex;
        }
    }

    public void buildToOutputStream(OutputStream outputStream)
            throws CDocException, CDocValidationException, IOException {
        validate();

        try {
            Envelope envelope;
            if (serverProperties == null) {
                envelope = Envelope.prepare(recipients, null);
            } else {
                // for encryption, do not init mTLS client as this might require smart-card
                envelope = Envelope.prepare(recipients, KeyCapsuleClientImpl.create(serverProperties, false));
            }
            envelope.encrypt(this.payloadFiles, outputStream);
        } catch (GeneralSecurityException ex) {
            throw new CDocException(ex);
        }
    }

    public void validate() throws CDocValidationException {
        validateRecipients();
        validatePayloadFiles();
    }

    void validateRecipients() throws CDocValidationException {
        if (this.recipients == null || this.recipients.isEmpty()) {
            throw new CDocValidationException("Must provide at least one recipient");
        }

        for (EncryptionKeyMaterial keyMaterial: recipients) {

            if (keyMaterial.getKey() instanceof PublicKey) {
                PublicKey publicKey = (PublicKey) keyMaterial.getKey();

                if ("EC".equals(publicKey.getAlgorithm())) {
                    ECPublicKey recipientPubKey = (ECPublicKey) publicKey;
                    String encoded = Base64.getEncoder().encodeToString(recipientPubKey.getEncoded());
                    try {
                        String oid = ECKeys.getCurveOid(recipientPubKey);
                        EllipticCurve curve;
                        try {
                            curve = EllipticCurve.forOid(oid);
                        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                            log.error("EC pub key curve ({}) is not supported. EC public key={}",
                                    oid, encoded);
                            throw new CDocValidationException("Invalid recipient key with key " + oid);
                        }

                        if (!curve.isValidKey(recipientPubKey)) {
                            log.error("EC pub key is not valid for curve {}. EC public key={}",
                                    curve.getName(), encoded);
                            throw new CDocValidationException("Recipient key not valid");
                        }
                    } catch (GeneralSecurityException gse) {
                        throw new CDocValidationException("Invalid recipient " + encoded, gse);
                    }
                } else if ("RSA".equals(publicKey.getAlgorithm())) {
                    // all RSA keys are considered good. Shorter will fail during encryption as OAEP takes some space
                    RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                    // no good way to check RSA key length as BigInteger can start with 00 and that changes bit-length
                    if (rsaPublicKey.getModulus().bitLength() <= 512) {
                        throw new CDocValidationException("RSA key does not meet length requirements");
                    }
                } else {
                    log.error("Unsupported public key alg {} for key {}",
                            publicKey.getAlgorithm(), keyMaterial.getLabel());
                    throw new CDocValidationException("Unsupported public key alg " + publicKey.getAlgorithm()
                            + "for key " + keyMaterial.getLabel());
                }

            } else if (keyMaterial.getKey() instanceof SecretKey) {
                if ((keyMaterial.getKey().getEncoded() == null)
                        || (keyMaterial.getKey().getEncoded().length < Crypto.SYMMETRIC_KEY_MIN_LEN_BYTES)) {
                    throw new CDocValidationException("Too short key for label: " + keyMaterial.getLabel());
                }
            } else {
                log.error("Unsupported key {} type: {}", keyMaterial.getLabel(), keyMaterial.getKey().getClass());
                throw new CDocValidationException("Unsupported key " + keyMaterial.getLabel());
            }

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
