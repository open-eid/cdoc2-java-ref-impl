package ee.cyber.cdoc2.crypto.keymaterial;

import ee.cyber.cdoc2.crypto.KeyLabelParams;

public interface Label {
    String getLabel();

    KeyLabelParams getKeyLabelParams();
}
