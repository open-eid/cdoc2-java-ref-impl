package ee.cyber.cdoc2.crypto.keymaterial.decrypt;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.crypto.jwt.InteractionParamsConfigurable;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import jakarta.annotation.Nullable;


/**
 * Represents key material required for decryption with the key derived from key shares.
 * Current object doesn't contain a key, but only data to retrieve decryption key material from
 * key-shares server.
 */
public class KeyShareDecryptionKeyMaterial implements DecryptionKeyMaterial, InteractionParamsConfigurable {

    private final AuthenticationIdentifier authIdentifier;
    private @Nullable InteractionParams interactionParams;

    /**
     * @param authIdentifier identifier for
                               {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
     */
    public KeyShareDecryptionKeyMaterial(AuthenticationIdentifier authIdentifier) {
        this.authIdentifier = authIdentifier;
    }

    @Override
    public Object getRecipientId() {
        return authIdentifier.getEtsiIdentifier();
    }

    @Override
    public EncryptionKeyOrigin getKeyOrigin() {
        return EncryptionKeyOrigin.KEY_SHARE;
    }

    public AuthenticationIdentifier getAuthIdentifier() {
        return this.authIdentifier;
    }

    @Override
    public void init(InteractionParams interactionParameters) {
        this.interactionParams = interactionParameters;
    }


    @Override
    public @Nullable InteractionParams getInteractionParams() {
        return this.interactionParams;
    }


}
