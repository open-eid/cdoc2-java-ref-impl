package ee.cyber.cdoc20.container.recipients;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.KekTools;
import ee.cyber.cdoc20.crypto.keymaterial.PasswordDecryptionKeyMaterial;
import ee.cyber.cdoc20.fbs.recipients.KDFAlgorithmIdentifier;
import ee.cyber.cdoc20.fbs.recipients.PBKDF2Capsule;


/**
 * PBKDF2 password-based recipient using password. POJO of flatbuffers
 * {@link PBKDF2Capsule fbs.recipients.PBKDF2Capsule} structure in CDOC header.
 */
public class PBKDF2Recipient extends Recipient {

    public static final int PBKDF2_ITERATIONS = 600_000; // recommended by NIST for HMAC-SHA-256

    private final byte[] encryptionSalt;
    private final byte[] passwordSalt;
    private final byte kdfAlgorithmIdentifier = KDFAlgorithmIdentifier.PBKDF2WithHmacSHA256;
    private final int kdfIterations = PBKDF2_ITERATIONS;

    public PBKDF2Recipient(
        byte[] encSalt,
        byte[] encFmk,
        String recipientLabel,
        byte[] passwordSalt
    ) {
        super(encFmk, recipientLabel);
        this.encryptionSalt = encSalt.clone();
        this.passwordSalt = passwordSalt;
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

    public byte getKdfAlgorithm() {
        return kdfAlgorithmIdentifier;
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
        throws GeneralSecurityException {

        return KekTools.deriveKekForPasswordDerivedKey(this,
            (PasswordDecryptionKeyMaterial) keyMaterial);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PBKDF2Recipient that = (PBKDF2Recipient) o;
        return Arrays.equals(encryptionSalt, that.encryptionSalt)
            && Arrays.equals(passwordSalt, that.passwordSalt)
            && kdfAlgorithmIdentifier == that.kdfAlgorithmIdentifier
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
