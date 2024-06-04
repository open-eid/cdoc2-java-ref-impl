package ee.cyber.cdoc2.crypto.keymaterial;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.SemanticIdentification;


/**
 * Represents key material required for encryption with the key derived from key shares.
 *
 * @param semanticIdentifier Identifiers for
 *                           {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 */
public record KeyShareEncryptionKeyMaterial(
    SemanticIdentification semanticIdentifier
) implements EncryptionKeyMaterial {

    @Override
    public String getLabel() {
        return semanticIdentifier.getIdentifier();
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }

}
