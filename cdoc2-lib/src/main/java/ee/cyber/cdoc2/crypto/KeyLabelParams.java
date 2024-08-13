package ee.cyber.cdoc2.crypto;

import java.util.Map;
import java.util.Objects;

import static ee.cyber.cdoc2.crypto.KeyLabelTools.urlEncodeValue;


/**
 * Key label parameters
 * @param encryptionKeyOrigin encryption key origin
 * @param keyLabelParams map of key label data fields
 */
public record KeyLabelParams(
    EncryptionKeyOrigin encryptionKeyOrigin,
    Map<String, String> keyLabelParams
) {

    public KeyLabelParams addParam(String key, String value) {
        keyLabelParams.put(key, urlEncodeValue(value));
        return this;
    }

    public boolean hasParam(KeyLabelTools.KeyLabelDataFields key) {
        Objects.requireNonNull(key);
        return this.keyLabelParams.containsKey(key.name());
    }

    public boolean isFromOrigin(EncryptionKeyOrigin origin) {
        Objects.requireNonNull(origin);
        return this.encryptionKeyOrigin.equals(origin);
    }

}
