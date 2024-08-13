package ee.cyber.cdoc2;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import ee.cyber.cdoc2.crypto.keymaterial.EncryptionKeyMaterial;

import static ee.cyber.cdoc2.KeyUtil.createPublicKey;
import static ee.cyber.cdoc2.KeyUtil.createSecretKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


class EncryptionKeyMaterialTest {

    @Test
    void shouldCreateEncryptionKeyMaterialFromPublicKey() throws Exception {
        EncryptionKeyMaterial encryptionKeyMaterial = EncryptionKeyMaterial.fromPublicKey(
            createPublicKey(),
            createKeyLabelParams(EncryptionKeyOrigin.PUBLIC_KEY)
        );

        assertEquals(EncryptionKeyOrigin.PUBLIC_KEY, encryptionKeyMaterial.getKeyOrigin());
    }

    @Test
    void shouldCreateEncryptionKeyMaterialFromSecretKey() throws Exception {
        KeyLabelParams keyLabelParams = createKeyLabelParams(
            EncryptionKeyOrigin.SECRET, "keyLabel"
        );
        EncryptionKeyMaterial encryptionKeyMaterial = EncryptionKeyMaterial.fromSecret(
            createSecretKey(), keyLabelParams
        );

        assertEquals(EncryptionKeyOrigin.SECRET, encryptionKeyMaterial.getKeyOrigin());
    }

    @Test
    void shouldFailToCreateEncryptionKeyMaterialFromPublicKey() throws Exception {
        PublicKey publicKey = createPublicKey();
        assertThrowsIllegalArgumentException(() ->
            EncryptionKeyMaterial.fromPublicKey(
                publicKey,
                createKeyLabelParams(EncryptionKeyOrigin.PASSWORD)
            )
        );
    }

    @Test
    void shouldFailToCreateEncryptionKeyMaterialFromSecretKeyWithWrongOrigin() {
        assertThrowsIllegalArgumentException(() ->
            EncryptionKeyMaterial.fromSecret(
                createSecretKey(),
                createKeyLabelParams(
                    EncryptionKeyOrigin.PASSWORD, "keyLabel"
                )
            )
        );
    }

    @Test
    void shouldFailToCreateEncryptionKeyMaterialFromSecretKeyWithMissingLabel() {
        assertThrowsIllegalArgumentException(() ->
            EncryptionKeyMaterial.fromSecret(
                createSecretKey(),
                createKeyLabelParams(EncryptionKeyOrigin.SECRET)
            )
        );
    }

    private KeyLabelParams createKeyLabelParams(EncryptionKeyOrigin keyOrigin) {
        return new KeyLabelParams(keyOrigin, new HashMap<>());
    }

    private KeyLabelParams createKeyLabelParams(EncryptionKeyOrigin keyOrigin, String keyLabel) {
        return new KeyLabelParams(keyOrigin, Map.of(
            KeyLabelTools.KeyLabelDataFields.LABEL.name(), keyLabel
        ));
    }

    private void assertThrowsIllegalArgumentException(Executable validation) {
        assertThrows(IllegalArgumentException.class, validation);
    }

}
