package ee.cyber.cdoc20;

import ee.cyber.cdoc20.container.Envelope;
import ee.cyber.cdoc20.crypto.Crypto;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.ECKeys.EllipticCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;

/**
 * CDocBuilder for building CDOCs using ECC public keys.
 */
public class EccPubKeyCDocBuilder {
    private static final Logger log = LoggerFactory.getLogger(EccPubKeyCDocBuilder.class);

    private List<File> payloadFiles;
    private List<ECPublicKey> recipients;
    private KeyPair senderKeyPair;

    private boolean generateSenderKeyPair = true;

    private EllipticCurve curve;

    @SuppressWarnings("checkstyle:HiddenField")
    public EccPubKeyCDocBuilder withPayloadFiles(List<File> payloadFiles) {
        this.payloadFiles = payloadFiles;
        return this;
    }

    public EccPubKeyCDocBuilder withRecipients(List<ECPublicKey> recipientsPubKeys) {
        this.recipients = recipientsPubKeys;
        return this;
    }

    /**
     * Define that all generated or provided EC keys must use curveName.
     * Currently, only {@value ee.cyber.cdoc20.crypto.ECKeys#SECP_384_R_1} is supported
     * @param curveName
     * @return
     */
    public EccPubKeyCDocBuilder withCurve(String curveName) {
        this.curve = EllipticCurve.forName(curveName);
        return this;
    }

    /**
     *
     * @param sender senders EC key pair
     * @return this builder
     */
    public EccPubKeyCDocBuilder withSender(KeyPair sender) {
        this.generateSenderKeyPair = false;
        this.senderKeyPair = sender;
        return this;
    }

    /**
     * For each recipient, generate sender key pair
     * @return this builder
     */
    public EccPubKeyCDocBuilder withGeneratedSender() {
        this.generateSenderKeyPair = true;
        this.senderKeyPair = null;
        return this;
    }

    public void buildToFile(File outputCDocFile) throws CDocException, IOException, CDocValidationException {
        try (OutputStream outputStream = new FileOutputStream(outputCDocFile)) {
            buildToOutputStream(outputStream);
        }
    }

    public void buildToOutputStream(OutputStream outputStream)
            throws CDocException, CDocValidationException, IOException {

        if (this.curve == null) {
            EllipticCurve recipients0Curve = extractCurveFromRecipients();
            log.warn("Curve not specified, setting to {}", recipients0Curve.getName());
            this.curve = recipients0Curve;
        }

        validate();

        try {
            Envelope envelope = (this.generateSenderKeyPair)
                    ? Envelope.prepare(this.curve, recipients)
                    : Envelope.prepare(Crypto.generateFileMasterKey(), this.curve, senderKeyPair, recipients);
            envelope.encrypt(this.payloadFiles, outputStream);
        } catch (GeneralSecurityException ex) {
            throw new CDocException(ex);
        }
    }

    private EllipticCurve extractCurveFromRecipients() throws CDocValidationException {
        if ((recipients != null) && !recipients.isEmpty()) {
            try {
                return EllipticCurve.forOid(ECKeys.getCurveOid(recipients.get(0)));
            } catch (GeneralSecurityException gse) {
                String x509encoded = Base64.getEncoder().encodeToString(recipients.get(0).getEncoded());
                log.error("Invalid recipient key {}", x509encoded);
                throw new CDocValidationException("Invalid recipient", gse);
            }
        }

        return null;
    }

    public void validate() throws CDocValidationException {


        if (!generateSenderKeyPair) {
            validateSender();
        }
        validateRecipients();
        validatePayloadFiles();
    }

    void validateRecipients() throws CDocValidationException {
        if (this.recipients == null || this.recipients.isEmpty()) {
            throw new CDocValidationException("Must provide at least one recipient");
        }

        if (this.curve == null) {
            throw new CDocValidationException("Must specify Elliptic Curve");
        }


        for (ECPublicKey recipientPubKey : recipients) {
            String oid;
            String encoded = Base64.getEncoder().encodeToString(recipientPubKey.getEncoded());
            try {
                oid = ECKeys.getCurveOid(recipientPubKey);
                if ((oid == null) || !oid.equals(curve.getOid()) || !curve.isValidKey(recipientPubKey)) {
                    log.error("EC pub key curve ({}) is not supported or key is not on curve. EC public key={}",
                            oid, encoded);
                    throw new CDocValidationException("Recipient key not valid");
                }
            } catch (GeneralSecurityException gse) {

                throw new CDocValidationException("Invalid recipient " + encoded, gse);
            }

        }
    }

    void validateSender() throws CDocValidationException {
        if (this.senderKeyPair == null) {
            throw new CDocValidationException("Must provide sender key pair");
        }

        if (this.curve == null) {
            throw new CDocValidationException("Must specify Elliptic Curve");
        }


        if (!(this.senderKeyPair.getPublic() instanceof ECPublicKey)) {
            throw new CDocValidationException("Sender key pair must be EC key pair");
        }

        String pubKeyOid;
        String privKeyOid;
        try {
            pubKeyOid = ECKeys.getCurveOid((ECKey) this.senderKeyPair.getPublic());
            privKeyOid = ECKeys.getCurveOid((ECKey) this.senderKeyPair.getPrivate());
        } catch (GeneralSecurityException gse) {
            throw new CDocValidationException("Invalid sender key ", gse);
        }
        if ((pubKeyOid == null) || (privKeyOid == null) || (!pubKeyOid.equals(privKeyOid))
                || (!pubKeyOid.equals(this.curve.getOid()))) {
            log.error("Sender EC key curve validation failed. Curve={}, privKey={}, pubKey={}",
                    this.curve.getOid(), privKeyOid, pubKeyOid);
            throw new CDocValidationException("Recipient oid doesn't match with curve " );
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
