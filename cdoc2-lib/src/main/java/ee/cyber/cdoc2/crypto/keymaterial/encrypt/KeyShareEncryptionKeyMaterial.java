package ee.cyber.cdoc2.crypto.keymaterial.encrypt;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.SemanticIdentification;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;


/**
 * Represents key material required for encryption with the key derived from key shares.
 * @param semanticIdentifier Identifiers for
 *                           {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 * @param keyLabel (ETSI) identifier for the encryption key
 */
public record KeyShareEncryptionKeyMaterial(
    SemanticIdentification semanticIdentifier,
    String keyLabel
) implements EncryptionKeyMaterial {

    @Override
    public String getLabel() {
        return keyLabel;
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }

    public SemanticIdentification.AuthenticationType getAuthenticationType() {
        String identifier = semanticIdentifier.getIdentifier();
        int colon = identifier.indexOf(":");
        return SemanticIdentification.AuthenticationType.of(identifier.substring(0, colon));
    }

}
