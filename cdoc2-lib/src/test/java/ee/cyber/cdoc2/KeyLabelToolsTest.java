package ee.cyber.cdoc2;

import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import ee.cyber.cdoc2.crypto.AuthenticationIdentifier;
import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_LABEL_FILE_NAME_PROPERTY;
import static ee.cyber.cdoc2.crypto.AuthenticationIdentifier.createSemanticsIdentifier;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.convertKeyLabelParamsMapToString;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createCertKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createEIdKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createKeySharesKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createPublicKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSecretKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSymmetricKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.extractKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.getPlainKeyLabel;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.isFormatted;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.keyLabelParamsForDisplaying;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.toDataUrlScheme;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.urlDecodeValue;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.urlEncodeValue;
import static org.junit.jupiter.api.Assertions.*;


class KeyLabelToolsTest {

    static final String PLAIN_KEY_LABEL = "plainKeyLabel";
    static final String FORMATTED_KEY_LABEL = "data:,V=1&TYPE=pw&LABEL=" + PLAIN_KEY_LABEL;

    @Test
    void testExtractKeyLabelParams() {
        final String defaultPubKeyFormattedLabel = "data:,V=1&TYPE=pw";
        Map<String, String> paramsMap = extractKeyLabelParams(defaultPubKeyFormattedLabel);

        Map<String, String> expected = Map.of(
            "v", "1",
            "type", "pw"
        );

        assertEquals(expected, paramsMap);
    }

    @Test
    void testKeyLabelExtractionInSensitiveCase() {
        Map<String, String> paramsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        paramsMap.put("v", "1");
        paramsMap.put("tYpE", "pw");

        KeyLabelParams params = new KeyLabelParams(
            EncryptionKeyOrigin.PUBLIC_KEY,
            paramsMap
        );

        String formattedKeyLabel = KeyLabelTools.formatKeyLabel(params);
        assertDoesNotThrow(() -> KeyLabelTools.extractKeyLabel(formattedKeyLabel));
    }

    @Test
    void testKeyLabelExtractionWithBase64EncodedData() {
        KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
            EncryptionKeyOrigin.PASSWORD, PLAIN_KEY_LABEL
        );
        String stringParams = convertKeyLabelParamsMapToString(keyLabelParams.keyLabelParams());

        String encodedKeyLabelData
            = Base64.encodeBase64String(stringParams.getBytes(StandardCharsets.UTF_8));
        String formattedKeyLabel = toDataUrlScheme(encodedKeyLabelData);
        assertTrue(formattedKeyLabel.contains(";base64"));

        String extractedKeyLabel = KeyLabelTools.extractKeyLabel(formattedKeyLabel);
        assertEquals(PLAIN_KEY_LABEL, extractedKeyLabel);
    }

    @Test
    void testKeyLabelExtractionWithBase64ReferenceButNotEncodedData() {
        KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
            EncryptionKeyOrigin.PASSWORD, PLAIN_KEY_LABEL
        );
        String stringParams = convertKeyLabelParamsMapToString(keyLabelParams.keyLabelParams());

        String formattedKeyLabel = "data:;base64," + stringParams;
        assertTrue(formattedKeyLabel.contains(";base64"));

        String extractedKeyLabel = KeyLabelTools.extractKeyLabel(formattedKeyLabel);
        assertEquals(PLAIN_KEY_LABEL, extractedKeyLabel);
    }

    @Test
    void testPasswordKeyLabelParamsCreation() {
        KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
            EncryptionKeyOrigin.PASSWORD, PLAIN_KEY_LABEL
        );

        assertEquals(
            PLAIN_KEY_LABEL,
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.LABEL
            )
        );
    }

    @Test
    void testPublicKeyLabelParamsCreation() {
        KeyLabelParams keyLabelParams = createPublicKeyLabelParams(null, null);

        assertEquals(
            "pub_key",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.TYPE
            )
        );
    }

    @Test
    void testPublicKeyLabelParamsCreationWithLabel() {
        KeyLabelParams keyLabelParams = createPublicKeyLabelParams("keyLabel", null);

        assertEquals(
            "keyLabel",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.LABEL
            )
        );
    }

    @Test
    void testPublicKeyLabelParamsCreationWithFile() {
        KeyLabelParams keyLabelParams = createPublicKeyLabelParams(
            null,
            new File("file_name")
        );

        assertEquals(
            "file_name",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.FILE
            )
        );
    }

    @Test
    void testPublicKeyLabelParamsCreationWhenFileNotAllowedToAdd() {
        System.setProperty(KEY_LABEL_FILE_NAME_PROPERTY, "false");
        KeyLabelParams keyLabelParams = createPublicKeyLabelParams(
            null,
            new File("file_name")
        );

        assertNull(keyLabelParams.keyLabelParams()
            .get(KeyLabelTools.KeyLabelDataFields.FILE.name()));

        System.setProperty(KEY_LABEL_FILE_NAME_PROPERTY, "true");
    }

    @Test
    void testKeyLabelDataDecodingFromWithBase64() {
        KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
            EncryptionKeyOrigin.PASSWORD, PLAIN_KEY_LABEL
        );
        String stringParams = convertKeyLabelParamsMapToString(keyLabelParams.keyLabelParams());

        String encodedKeyLabelData
            = Base64.encodeBase64String(stringParams.getBytes(StandardCharsets.UTF_8));
        String formattedKeyLabel = toDataUrlScheme(encodedKeyLabelData);
        Map<String, String> extractedKeyLabelParams = extractKeyLabelParams(formattedKeyLabel);

        assertEquals(
            PLAIN_KEY_LABEL,
            extractedKeyLabelParams.get(KeyLabelTools.KeyLabelDataFields.LABEL.name())
        );
    }

    @Test
    void testCertificateLabelParamsCreation() {
        KeyLabelParams keyLabelParams = createCertKeyLabelParams(
            "keyLabel", "certSha1", new File("file_name")
        );

        assertEquals(
            "keyLabel",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.CN
            )
        );
        assertEquals(
            "certSha1",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.CERT_SHA1
            )
        );
        assertEquals(
            "file_name",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.FILE
            )
        );
    }

    @Test
    void testCertificateLabelParamsCreationWhenFileNotAllowedToAdd() {
        System.setProperty(KEY_LABEL_FILE_NAME_PROPERTY, "false");
        KeyLabelParams keyLabelParams = createCertKeyLabelParams(
            null, null, new File("file_name")
        );

        assertNull(keyLabelParams.keyLabelParams()
            .get(KeyLabelTools.KeyLabelDataFields.FILE.name()));

        System.setProperty(KEY_LABEL_FILE_NAME_PROPERTY, "true");
    }

    @Test
    void testEIdLabelParamsCreation() {
        KeyLabelParams keyLabelParams = createEIdKeyLabelParams(
            "Common,Name,IdentityCode",
            BigInteger.valueOf(123456),
            KeyLabelTools.KeyLabelType.CERT.getName()
        );

        assertEquals(
            "Common,Name,IdentityCode",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.CN
            )
        );
        assertEquals(
            "123456",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.SERIAL_NUMBER
            )
        );
        assertEquals(
            "Name",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.FIRST_NAME
            )
        );
        assertEquals(
            "Common",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.LAST_NAME
            )
        );
    }

    @Test
    void testSecretKeyLabelParamsCreation() {
        KeyLabelParams keyLabelParams = createSecretKeyLabelParams("keyLabel");

        assertEquals(
            "keyLabel",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.LABEL
            )
        );
    }

    @Test
    void testKeySharesKeyLabelParamsCreation() {
        SemanticsIdentifier semanticsIdentifier = createSemanticsIdentifier("30303039914");
        AuthenticationIdentifier authIdentifier = AuthenticationIdentifier
            .forKeyShares(semanticsIdentifier, AuthenticationIdentifier.AuthenticationType.SID);
        KeyLabelParams keyLabelParams
            = createKeySharesKeyLabelParams(authIdentifier.getEtsiIdentifier());

        assertEquals(
            "etsi/PNOEE-30303039914",
            getDecodedKeyLabelParamValue(
                keyLabelParams.keyLabelParams(),
                KeyLabelTools.KeyLabelDataFields.SN
            )
        );
    }

    @Test
    void shouldReturnPlainKeyLabelIfEncryptedWithPlainText() {
        final String plainKeyLabel = "plainKeyLabel";
        String keyLabelForDecryption = getPlainKeyLabel(plainKeyLabel);
        assertEquals(plainKeyLabel, keyLabelForDecryption);
    }

    @Test
    void shouldReturnPlainKeyLabelIfEncryptedWithFormattedForm() {
        String keyLabelForDecryption = getPlainKeyLabel(FORMATTED_KEY_LABEL);
        assertEquals(PLAIN_KEY_LABEL, keyLabelForDecryption);
    }

    @Test
    void shouldReturnNullIfLabelParamIsMissingInEncryptionKeyLabel() {
        final String keyLabelWithMissingLabelParam = "data:,V=1&TYPE=pw";
        String keyLabelForDecryption = getPlainKeyLabel(keyLabelWithMissingLabelParam);
        assertNull(keyLabelForDecryption);
    }

    @Test
    void validateKeyLabelParameterValue() {
        String pubKeyName = "pw==";
        String urlEncodedValue = urlEncodeValue(pubKeyName);
        String decodedValue = urlDecodeValue(urlEncodedValue);
        assertEquals(pubKeyName.length(), decodedValue.length());
    }

    @Test
    void shouldAssertThatKeyLabelIsFormatted() {
        assertTrue(isFormatted(FORMATTED_KEY_LABEL));
    }

    @Test
    void shouldAssertThatKeyLabelIsNotFormatted() {
        assertFalse(isFormatted("plain_key_label"));
    }

    @Test
    void shouldExtractKeyLabelFromFormattedForm() {
        Map<String, String> keyLabelParams = extractKeyLabelParams(FORMATTED_KEY_LABEL);
        assertEquals(
            "plainKeyLabel",
            keyLabelParams.get(KeyLabelTools.KeyLabelDataFields.LABEL.name())
        );
    }

    @Test
    void shouldExtractPlainKeyLabel() {
        Map<String, String> keyLabelParams = extractKeyLabelParams("plainKeyLabel");
        assertEquals(
            "plainKeyLabel",
            keyLabelParams.get(KeyLabelTools.KeyLabelDataFields.LABEL.name())
        );
    }

    @Test
    void shouldDisplayKeyLabelParams() {
        Map<String, String> paramsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        paramsMap.put("v", "1");
        paramsMap.put("type", "secret");
        paramsMap.put("label", "keyLabel");

        String keyLabelParamsString = keyLabelParamsForDisplaying(paramsMap);
        String expectedKeyLabel = "V:1, LABEL:keyLabel, TYPE:secret";
        assertEqualKeyLabels(
            expectedKeyLabel,
            keyLabelParamsString
        );
    }

    private String getDecodedKeyLabelParamValue(
        Map<String, String> keyLabelParams,
        KeyLabelTools.KeyLabelDataFields dataFieldKey
    ) {
        return urlDecodeValue(
            keyLabelParams.get(dataFieldKey.name())
        );
    }

    private void assertEqualKeyLabels(String expectedKeyLabel, String actualOutputKeyLabel) {
        Map<String, String> expectedParams = convertStringToKeyLabelParamsMap(expectedKeyLabel);
        Map<String, String> actualParams = convertStringToKeyLabelParamsMap(actualOutputKeyLabel);

        for (var entry : expectedParams.entrySet()) {
            assertTrue(actualParams.containsKey(entry.getKey()));
            assertTrue(actualParams.containsValue(entry.getValue()));
        }
    }

    private static Map<String, String> convertStringToKeyLabelParamsMap(String data) {
        Map<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        String[] parts = data.split(", ");

        for (String keyValue : parts) {
            String[] params = keyValue.split(":");
            result.put(params[0], params[1]);
        }

        return result;
    }

}
