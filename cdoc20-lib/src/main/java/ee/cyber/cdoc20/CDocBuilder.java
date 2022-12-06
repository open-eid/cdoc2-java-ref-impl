package ee.cyber.cdoc20;

import ee.cyber.cdoc20.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CDocBuilder for building CDOCs using EC (secp384r1) or RSA public keys.
 */
public class CDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(CDocBuilder.class);

    private List<File> payloadFiles;
    private Map<PublicKey, String> recipients;
    private Properties serverProperties;

    public CDocBuilder withPayloadFiles(List<File> files) {
        this.payloadFiles = files;
        return this;
    }

    public CDocBuilder withRecipients(Map<PublicKey, String> recipientsPubKeys) {
        this.recipients = recipientsPubKeys;
        return this;
    }

    public CDocBuilder withServerProperties(Properties p) {
        this.serverProperties = p;
        return this;
    }

    public void buildToFile(File outputCDocFile) throws CDocException, IOException, CDocValidationException {
        try (OutputStream outputStream = new FileOutputStream(outputCDocFile)) {
            buildToOutputStream(outputStream);
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
                // for encryption don't init mTLS client as this might require smart-card
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

        for (Map.Entry<PublicKey, String> keyLabel : recipients.entrySet()) {
            String oid;
            PublicKey publicKey = keyLabel.getKey();

            if ("EC".equals(publicKey.getAlgorithm())) {
                ECPublicKey recipientPubKey = (ECPublicKey) publicKey;
                String encoded = Base64.getEncoder().encodeToString(recipientPubKey.getEncoded());
                try {
                    oid = ECKeys.getCurveOid(recipientPubKey);
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
