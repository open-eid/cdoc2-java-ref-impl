package ee.cyber.cdoc20.container.recipients;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.CDocException;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.KekTools;
import ee.cyber.cdoc20.crypto.keymaterial.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc20.fbs.recipients.RsaKeyDetails;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * RSA-OAEP recipient using RsaKeyDetails. POJO of flatbuffers
 *  {@link RsaKeyDetails recipients.RsaKeyDetails} structure in CDOC header.
 */
public class RSAServerKeyRecipient extends RSARecipient implements ServerRecipient {

    private final String keyServerId;
    private final String transactionId;

    public RSAServerKeyRecipient(RSAPublicKey recipient, String keyServerId, String transactionId,
            byte[] encryptedFmk, String recipientLabel) {
        super(recipient, encryptedFmk, recipientLabel);
        this.keyServerId = keyServerId;
        this.transactionId = transactionId;
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
        RSAServerKeyRecipient that = (RSAServerKeyRecipient) o;
        return Objects.equals(keyServerId, that.keyServerId) && Objects.equals(transactionId, that.transactionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), keyServerId, transactionId);
    }

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
        throws GeneralSecurityException, CDocException {
        if (keyMaterial instanceof KeyPairDecryptionKeyMaterial keyPairKeyMaterial) {
            return KekTools.deriveKekForRsaServer(
                this,
                keyPairKeyMaterial,
                factory
            );
        }

        throw new GeneralSecurityException(
            "Unsupported key material type for recipient " + keyMaterial.getRecipientId()
        );
    }

    @Override
    public int serialize(FlatBufferBuilder builder) {
        return RecipientSerializer.serialize(this, builder);
    }
}
