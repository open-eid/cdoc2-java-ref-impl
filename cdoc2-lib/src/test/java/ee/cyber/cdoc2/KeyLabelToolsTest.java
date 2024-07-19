package ee.cyber.cdoc2;

import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class KeyLabelToolsTest {

    static final KeyLabelParams defaultPubKeyParams =
        KeyLabelTools.createPublicKeyLabelParams(null, null);
    @Test
    void testFormatKeyLabel() {
        String actual = KeyLabelTools.formatKeyLabel(defaultPubKeyParams);
        String expected = "data:,V=1&TYPE=pub_key";
        assertEquals(expected, actual);
    }

    @Test
    void testExtractKeyLabelParams() {
        final String defaultPubKeyFormattedLabel = "data:,V=1&TYPE=pub_key";
        Map<String, String> paramsMap = KeyLabelTools.extractKeyLabelParams(defaultPubKeyFormattedLabel);

        Map<String, String> expected = Map.of(
            "V", "1",
            "TYPE", "pub_key"
        );

        assertEquals(expected, paramsMap);
    }
}
