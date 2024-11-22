package ee.cyber.cdoc2.crypto.keymaterial.decrypt;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.SemanticIdentification;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;


/**
 * Represents key material required for decryption with the key derived from key shares.
 * Current object doesn't contain a key, but only data for further KEK derivation.
 * @param semanticIdentifier identifier for
 *                          {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 */
public record KeyShareDecryptionKeyMaterial(
    SemanticIdentification semanticIdentifier
) implements DecryptionKeyMaterial {

    @Override
    public Object getRecipientId() {
        return semanticIdentifier.getEtsiIdentifier();
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }

}
