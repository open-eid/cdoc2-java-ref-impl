package ee.cyber.cdoc20.container.recipients;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.CDocException;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import ee.cyber.cdoc20.crypto.KekTools;
import ee.cyber.cdoc20.fbs.recipients.EccKeyDetails;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * ECC recipient using EccKeyDetails. POJO of
 * {@link EccKeyDetails recipients.EccKeyDetails} in CDOC header.
 */
public class EccServerKeyRecipient extends EccRecipient implements ServerRecipient {
    private final String keyServerId;
    private final String transactionId;

    public EccServerKeyRecipient(EllipticCurve eccCurve, ECPublicKey recipientPubKey,
                                 String keyServerId, String transactionId, byte[] encryptedFmk,
                                 String recipientPubKeyLabel) {
        super(eccCurve, recipientPubKey, recipientPubKeyLabel, encryptedFmk);
        this.keyServerId = keyServerId;
        this.transactionId = transactionId;
    }

    public byte[] getRecipientPubKeyTlsEncoded() {
        return ECKeys.encodeEcPubKeyForTls(this.ellipticCurve, this.recipientPubKey);
    }

    @Override
    public String getKeyServerId() {
        return keyServerId;
    }

    @Override
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

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
            throws GeneralSecurityException, CDocException {
        return KekTools.deriveKekForEccServer(this, keyMaterial, factory);
    }


    @Override
    public int serialize(FlatBufferBuilder builder) {
        return RecipientSerializer.serialize(this, builder);
    }
}
