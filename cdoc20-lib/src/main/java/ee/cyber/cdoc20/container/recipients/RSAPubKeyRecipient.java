package ee.cyber.cdoc20.container.recipients;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.KekTools;
import ee.cyber.cdoc20.fbs.recipients.RSAPublicKeyCapsule;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * RSA-OAEP recipient using RSAPublicKey. POJO of flatbuffers
 * {@link RSAPublicKeyCapsule fbs.recipients.RSAPublicKeyCapsule} structure in CDOC header.
 */
public class RSAPubKeyRecipient extends RSARecipient {

    private final byte[] encryptedKek;

    public RSAPubKeyRecipient(RSAPublicKey recipient,
                              byte[] encryptedKek,
                              byte[] encryptedFmk, String recipientLabel) {
        super(recipient, encryptedFmk, recipientLabel);
        this.encryptedKek = encryptedKek;
    }

    public byte[] getEncryptedKek() {
        return encryptedKek;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        RSAPubKeyRecipient that = (RSAPubKeyRecipient) o;
        return Arrays.equals(encryptedKek, that.encryptedKek);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(encryptedKek);
        return result;
    }

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
            throws GeneralSecurityException {

        return KekTools.deriveKekForRsa(this, keyMaterial);
    }

    @Override
    public int serialize(FlatBufferBuilder builder) {
        return RecipientSerializer.serialize(this, builder);
    }
}
