package ee.cyber.cdoc2.container.recipients;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.flatbuffers.FlatBufferBuilder;

import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.crypto.KeyShareUri;
import ee.cyber.cdoc2.crypto.KeyShareRecipientType;
import ee.cyber.cdoc2.crypto.SharesScheme;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.KeyShareDecryptionKeyMaterial;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;


/**
 * KeyShares recipient using the list of key shares. POJO of flatbuffers
 * {@link KeySharesCapsule fbs.recipients.KeySharesCapsule} structure in CDOC header.
 */
public class KeySharesRecipient extends Recipient {

    private final List<KeyShareUri> shares;
    private final byte[] salt;
    private final KeyShareRecipientType recipientType;
    private final SharesScheme sharesScheme;

    public KeySharesRecipient(
        byte[] encFmk,
        String recipientId,
        List<KeyShareUri> shares,
        byte[] salt,
        KeyShareRecipientType recipientType,
        SharesScheme sharesScheme
    ) {
        super(encFmk, recipientId);
        this.shares = shares;
        this.salt = salt;
        this.recipientType = recipientType;
        this.sharesScheme = sharesScheme;
    }

    @Override
    public Object getRecipientId() {
        return recipientKeyLabel;
    }

    public List<KeyShareUri> getKeyShares() {
        return shares;
    }

    /**
     * Salt used to encrypt/decrypt CDOC2 container.
     */
    public byte[] getSalt() {
        return salt;
    }

    public KeyShareRecipientType getRecipientType() {
        return recipientType;
    }

    public SharesScheme getSharesScheme() {
        return sharesScheme;
    }

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
        throws GeneralSecurityException {
        if (keyMaterial instanceof KeyShareDecryptionKeyMaterial keyShareKeyMaterial) {
            // ToDo derive key in #2752
            return new byte[0];
        }

        throw new GeneralSecurityException(
            "Unsupported key material type for recipient " + keyMaterial.getRecipientId()
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        KeySharesRecipient that = (KeySharesRecipient) o;
        return shares.equals(that.shares)
            && Arrays.equals(salt, that.salt)
            && Objects.equals(recipientType, that.recipientType)
            && Objects.equals(sharesScheme, that.sharesScheme);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            super.hashCode(),
            shares,
            Arrays.hashCode(salt),
            recipientType,
            sharesScheme
        );
    }

    @Override
    public int serialize(FlatBufferBuilder builder) {
        // ToDo implement key serialization in #2752
        return 0;
    }

}
