package ee.cyber.cdoc20.container.recipients;

import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.container.CDocParseException;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.KekDerivable;
import ee.cyber.cdoc20.crypto.KekTools;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
/**
 * RSA-OAEP recipient using ServerRsa. POJO of flatbuffers
 *  {@link ee.cyber.cdoc20.fbs.recipients.ServerRsaDetails recipients.ServerRsaDetails} structure in CDOC header.
 */
public class RSAServerKeyRecipient extends RSARecipient implements KekDerivable, ServerRecipient {

    private final String keyServerId;
    private final String transactionId;

    public RSAServerKeyRecipient(RSAPublicKey recipient,
                                 String keyServerId, String transactionId,
                                 byte[] encryptedFmk,
                                 String recipientLabel) {
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
            throws GeneralSecurityException, ExtApiException, CDocParseException {

        return KekTools.deriveKekForRsaServer(this, keyMaterial, factory);
    }
}
