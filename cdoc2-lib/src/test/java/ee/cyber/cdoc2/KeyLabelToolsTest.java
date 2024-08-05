package ee.cyber.cdoc2;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;


class KeyLabelToolsTest {

    @Test
    void testExtractKeyLabelParams() {
        final String defaultPubKeyFormattedLabel = "data:,V=1&TYPE=pub_key";
        Map<String, String> paramsMap = KeyLabelTools.extractKeyLabelParams(defaultPubKeyFormattedLabel);

        Map<String, String> expected = Map.of(
            "v", "1",
            "type", "pub_key"
        );

        assertEquals(expected, paramsMap);
    }

    @Test
    void testKeyLabelExtractionInSensitiveCase() {
        Map<String, String> paramsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        paramsMap.put("v", "1");
        paramsMap.put("tYpE", "pub_key");

        KeyLabelParams params = new KeyLabelParams(
            EncryptionKeyOrigin.PUBLIC_KEY,
            paramsMap
        );

        String formattedKeyLabel = KeyLabelTools.formatKeyLabel(params);
        assertDoesNotThrow(() -> KeyLabelTools.extractKeyLabel(formattedKeyLabel));
    }

}
