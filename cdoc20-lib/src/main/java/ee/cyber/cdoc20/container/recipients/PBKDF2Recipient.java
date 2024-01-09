package ee.cyber.cdoc20.container.recipients;

import java.util.Arrays;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.KekTools;
import ee.cyber.cdoc20.fbs.recipients.PBKDF2Capsule;

/**
 * PBKDF2 password-based recipient using password. POJO of flatbuffers
 * {@link PBKDF2Capsule fbs.recipients.PBKDF2Capsule} structure in CDOC header.
 */
public class PBKDF2Recipient extends Recipient {

    private final byte[] salt;

    public PBKDF2Recipient(byte[] salt, byte[] encFmk, String recipientLabel) {
        super(encFmk, recipientLabel);
        this.salt = salt.clone();
    }

    @Override
    public Object getRecipientId() {
        return recipientKeyLabel;
    }

    public byte[] getSalt() {
        return salt;
    }

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory) {
        return KekTools.deriveKekForSymmetricKey(this, keyMaterial);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PBKDF2Recipient that = (PBKDF2Recipient) o;
        return Arrays.equals(salt, that.salt);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(salt);
        return result;
    }

    @Override
    public int serialize(FlatBufferBuilder builder) {
        return RecipientSerializer.serializePBKDF2Recipient(this, builder);
    }
}
