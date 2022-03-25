package ee.cyber.cdoc20;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class CDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(CDocBuilder.class);

    private List<String> payloadFiles;
    private List<ECPublicKey> recipients;
    private KeyPair senderKeyPair;

    public CDocBuilder withPayloadFiles(List<String> payloadFiles) {
        this.payloadFiles = payloadFiles;
        return this;
    }

//    public CDocBuilder withPayload(byte[] payload) {
//        return this;
//    }

    public CDocBuilder withRecipients(List<ECPublicKey> recipients) {
        this.recipients = recipients;
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

    public void buildToOutputStream(OutputStream outputStream) throws CDocValidationException{
        validate();
    }

    void validate() throws CDocValidationException {
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

        for(String fileName: payloadFiles) {
            File file = new File(fileName);

            if (!(file.exists() && file.isFile() && file.canRead())) {
                log.error("Invalid payload file {}", fileName);
                throw new CDocValidationException("Invalid payload file "+fileName);
            }
        }
    }
}
