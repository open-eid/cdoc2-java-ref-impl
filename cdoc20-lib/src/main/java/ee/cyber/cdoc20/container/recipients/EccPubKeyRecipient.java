package ee.cyber.cdoc20.container.recipients;

import com.google.flatbuffers.FlatBufferBuilder;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.crypto.EllipticCurve;
import ee.cyber.cdoc20.crypto.KekTools;
import ee.cyber.cdoc20.crypto.keymaterial.KeyPairDecryptionKeyMaterial;
import ee.cyber.cdoc20.fbs.recipients.ECCPublicKeyCapsule;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * ECC recipient using ECCPublicKey. POJO of
 * {@link ECCPublicKeyCapsule recipients.ECCPublicKeyCapsule} in CDOC header.
 */
public class EccPubKeyRecipient extends EccRecipient {

    private final ECPublicKey senderPubKey;

    public EccPubKeyRecipient(EllipticCurve eccCurve, ECPublicKey recipient, ECPublicKey sender,
                              byte[] encFmk, String recipientLabel) {
        super(eccCurve, recipient, recipientLabel, encFmk);
        this.senderPubKey = sender;
    }

    public ECPublicKey getSenderPubKey() {
        return senderPubKey;
    }

    /**
     * Recipient ECC public key in TLS 1.3 format (specified in RFC 8446) in bytes
     */
    public byte[] getSenderPubKeyTlsEncoded() {
        return ECKeys.encodeEcPubKeyForTls(this.ellipticCurve, this.senderPubKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EccPubKeyRecipient that = (EccPubKeyRecipient) o;
        return senderPubKey.equals(that.senderPubKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), senderPubKey);
    }

    @Override
    public byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
        throws GeneralSecurityException {
        if (keyMaterial instanceof KeyPairDecryptionKeyMaterial keyPairKeyMaterial) {
            return KekTools.deriveKekForEcc(this, keyPairKeyMaterial);
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
