package ee.cyber.cdoc2.crypto.keymaterial;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;

public interface LabeledPassword extends Label {
    char[] getPassword();

    @Override
    default KeyLabelParams getKeyLabelParams() {
        return KeyLabelTools.createSymmetricKeyLabelParams(EncryptionKeyOrigin.PASSWORD, this.getLabel());
    }
}
