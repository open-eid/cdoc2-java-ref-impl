package ee.cyber.cdoc2.crypto.keymaterial;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public interface LabeledSecret extends Label {

    byte[] getSecret();

    @Override
    default KeyLabelParams getKeyLabelParams() {
        return KeyLabelTools.createSymmetricKeyLabelParams(EncryptionKeyOrigin.SECRET, this.getLabel());
    }

    default SecretKey getSecretKey() {
        return new SecretKeySpec(getSecret(), "");
    }

}
