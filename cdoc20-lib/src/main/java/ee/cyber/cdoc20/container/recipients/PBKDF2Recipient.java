package ee.cyber.cdoc20.container.recipients;

import java.util.Arrays;
import java.util.Objects;

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

    private final byte[] encryptionSalt;
    private final byte[] passwordSalt;
    private final String kdfAlgorithmIdentifier;
    private final int kdfIterations;

    public PBKDF2Recipient(
        byte[] encSalt,
        byte[] encFmk,
        String recipientLabel,
        byte[] passwordSalt,
        String kdfAlgorithmIdentifier,
        int kdfIterations
    ) {
        super(encFmk, recipientLabel);
        this.encryptionSalt = encSalt.clone();
        this.passwordSalt = passwordSalt;
        this.kdfAlgorithmIdentifier = kdfAlgorithmIdentifier;
        this.kdfIterations = kdfIterations;
    }

    @Override
    public Object getRecipientId() {
        return recipientKeyLabel;
    }

    /**
     * Salt used to encrypt/decrypt CDOC2 container.
     */
    public byte[] getEncryptionSalt() {
        return encryptionSalt;
    }

    /**
     * Salt used to derive the symmetric key from the password.
     */
    public byte[] getPasswordSalt() {
        return passwordSalt;
    }

    public String getKdfAlgorithm() {
        return kdfAlgorithmIdentifier;
    }

    public int getKdfIterations() {
        return kdfIterations;
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
        return Arrays.equals(encryptionSalt, that.encryptionSalt)
            && Arrays.equals(passwordSalt, that.passwordSalt)
            && kdfAlgorithmIdentifier.equals(that.kdfAlgorithmIdentifier)
            && kdfIterations == that.kdfIterations;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            Arrays.hashCode(encryptionSalt),
            Arrays.hashCode(passwordSalt),
            kdfAlgorithmIdentifier,
            kdfIterations
        );
    }

    @Override
    public int serialize(FlatBufferBuilder builder) {
        return RecipientSerializer.serializePBKDF2Recipient(this, builder);
    }
}
