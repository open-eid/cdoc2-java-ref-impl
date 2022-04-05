package ee.cyber.cdoc20;

import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.crypto.Crypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class CDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(CDocBuilder.class);

    private List<File> payloadFiles;
    private List<ECPublicKey> recipients;
    private KeyPair senderKeyPair;

    @SuppressWarnings("checkstyle:HiddenField")
    public CDocBuilder withPayloadFiles(List<File> payloadFiles) {
        this.payloadFiles = payloadFiles;
        return this;
    }

    public CDocBuilder withRecipients(List<ECPublicKey> recipientsPubKeys) {
        this.recipients = recipientsPubKeys;
        return this;
    }

    /**
     *
     * @param sender senders EC key pair
     * @return this builder
     */
    public CDocBuilder withSender(KeyPair sender) {
        this.senderKeyPair = sender;
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
            Envelope envelope = Envelope.prepare(Crypto.generateFileMasterKey(), senderKeyPair, recipients);
            envelope.encrypt(this.payloadFiles, outputStream);
        } catch (GeneralSecurityException ex) {
            throw new CDocException(ex);
        }
    }

    public void validate() throws CDocValidationException {
        validatePayloadFiles();
        validateSender();
        validateRecipients();
    }

    void validateRecipients() throws CDocValidationException {
        if (this.recipients == null || this.recipients.isEmpty()) {
            throw new CDocValidationException("Must provide at least one recipient");
        }
    }

    void validateSender() throws CDocValidationException {
        if (this.senderKeyPair == null) {
            throw new CDocValidationException("Must provide sender key pair");
        }

        if (!(this.senderKeyPair.getPublic() instanceof ECPublicKey)) {
            throw new CDocValidationException("Sender key pair must be EC key pair");
        }
    }

    void validatePayloadFiles() throws CDocValidationException {
        if ((payloadFiles == null) || (payloadFiles.size() == 0)) {
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
