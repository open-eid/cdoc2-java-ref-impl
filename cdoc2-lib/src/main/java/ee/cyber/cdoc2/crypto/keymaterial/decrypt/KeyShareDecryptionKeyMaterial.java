package ee.cyber.cdoc2.crypto.keymaterial.decrypt;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;


/**
 * Represents key material required for decryption with the key derived from key shares.
 * Current object doesn't contain a key, but only data to retrieve decryption key material from
 * key-shares server.
 * @param authIdentifier identifier for
 *                          {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 * @param params optional parameters to drive user interaction for smart-id and mobile-id
 */
public record KeyShareDecryptionKeyMaterial(
    AuthenticationIdentifier authIdentifier, AuthenticationIdentifier.SidMidInteractionParams params
) implements DecryptionKeyMaterial {

    public KeyShareDecryptionKeyMaterial(AuthenticationIdentifier authIdentifier) {
        this(authIdentifier, null);
    }

    @Override
    public Object getRecipientId() {
        return authIdentifier.getEtsiIdentifier();
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }

}
