package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.crypto.ECKeys;

import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * ECC recipient using ECCServerKey. POJO of
 * {@link ee.cyber.cdoc20.fbs.recipients.ECCKeyServer recipients.ECCKeyServer} in CDOC header.
 */
public class EccServerKeyRecipient extends EccRecipient {
    private final String keyServerId;
    private final String transactionId;


    public EccServerKeyRecipient(ECKeys.EllipticCurve eccCurve, ECPublicKey recipientPubKey, String keyServerId,
                                 String transactionId, byte[] encryptedFmk) {
        super(eccCurve, recipientPubKey, encryptedFmk);
        this.keyServerId = keyServerId;
        this.transactionId = transactionId;
    }

    public byte[] getRecipientPubKeyTlsEncoded() {
        return ECKeys.encodeEcPubKeyForTls(this.ellipticCurve, this.recipientPubKey);
    }

    public String getKeyServerId() {
        return keyServerId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EccServerKeyRecipient that = (EccServerKeyRecipient) o;
        return Objects.equals(keyServerId, that.keyServerId)
                && Objects.equals(transactionId, that.transactionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), keyServerId, transactionId);
    }
}
