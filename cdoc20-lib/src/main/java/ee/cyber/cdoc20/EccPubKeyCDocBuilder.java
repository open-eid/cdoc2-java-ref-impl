package ee.cyber.cdoc20;

import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.util.KeyServerPropertiesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

/**
 * CDocBuilder for building CDOCs using ECC public keys.
 */
public class EccPubKeyCDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(EccPubKeyCDocBuilder.class);

    private List<File> payloadFiles;
    private List<ECPublicKey> recipients;
    private Properties serverProperties;

    @SuppressWarnings("checkstyle:HiddenField")
    public EccPubKeyCDocBuilder withPayloadFiles(List<File> payloadFiles) {
        this.payloadFiles = payloadFiles;
        return this;
    }

    public EccPubKeyCDocBuilder withRecipients(List<ECPublicKey> recipientsPubKeys) {
        this.recipients = recipientsPubKeys;
        return this;
    }

    public EccPubKeyCDocBuilder withServerProperties(Properties p) {
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
                envelope = Envelope.prepare(recipients);
            } else {
                envelope = Envelope.prepare(recipients, KeyServerPropertiesClient.create(serverProperties));
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

        for (ECPublicKey recipientPubKey : recipients) {
            String oid;
            String encoded = Base64.getEncoder().encodeToString(recipientPubKey.getEncoded());
            try {
                oid = ECKeys.getCurveOid(recipientPubKey);
                ECKeys.EllipticCurve curve;
                try {
                    curve = ECKeys.EllipticCurve.forOid(oid);
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


    void validatePayloadFiles() throws CDocValidationException {
        if ((payloadFiles == null) || (payloadFiles.isEmpty())) {
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
