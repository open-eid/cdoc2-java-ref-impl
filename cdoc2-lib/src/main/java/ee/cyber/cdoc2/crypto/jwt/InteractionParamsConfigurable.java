package ee.cyber.cdoc2.crypto.jwt;

/**
 * Interface that shows that Object supports configuring with InterActionParams
 * @see ee.cyber.cdoc2.crypto.keymaterial.decrypt.KeyShareDecryptionKeyMaterial
 */
public interface InteractionParamsConfigurable {
    void init(InteractionParams interactionParams);
    InteractionParams getInteractionParams();
}
