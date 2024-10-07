package ee.cyber.cdoc2.crypto;

import jakarta.annotation.Nullable;

import java.io.File;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.isKeyLabelFileNameAllowedToBeAdded;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.KeyLabelDataVersion.toNumbericString;


/**
 * Key label generation in machine parsable format
 */
public final class KeyLabelTools {

    private static final String DATA = "data:";
    private static final String DATA_DELIMITER = ",";
    private static final String DATA_PARAMETERS_DELIMITER = "&";
    private static final String DATA_PARAMETERS_KEY_VALUE_DELIMITER = "=";
    private static final String BASE_64_DELIMITER = ";";

    private static final Pattern BASE64_PATTERN = Pattern.compile(
        "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    );

    private KeyLabelTools() { }

    /**
     * Converts key label into machine-readable format.
     * @param keyLabelParams key label data parameters
     * @return Key Label in machine--readable format
     */
    public static String formatKeyLabel(KeyLabelParams keyLabelParams) {
        String keyLabelData = convertKeyLabelParamsMapToString(keyLabelParams.keyLabelParams());
        return toDataUrlScheme(keyLabelData);
    }

    /**
     * Validates key label format.
     * @param keyLabel encryption key label
     * @return Key Label in plain text
     */
    public static String getPlainKeyLabel(String keyLabel) {
        if (keyLabelIsFormatted(keyLabel)) {
            return extractKeyLabel(keyLabel);
        }

        return keyLabel;
    }

    /**
     * Extracts key label from machine-readable format.
     * @param keyLabel key label in machine-readable format
     * @return Key Label in plain text
     */
    public static String extractKeyLabel(String keyLabel) {
        Map<String, String> keyLabelParams = decodeKeyLabelParamsFromUrlScheme(keyLabel);

        return extractKeyLabelFromParams(keyLabelParams);
    }

    /**
     * Extracts key label parameters.
     * @param keyLabel key label. May be in machine-readable format or in plain text
     * @return map of Key Label parameters
     */
    public static Map<String, String> extractKeyLabelParams(String keyLabel) {
        boolean isFormatted = keyLabelIsFormatted(keyLabel);
        if (!isFormatted) {
            return Map.of(KeyLabelDataFields.LABEL.name(), keyLabel);
        }

        return decodeKeyLabelParamsFromUrlScheme(keyLabel);
    }

    private static Map<String, String> decodeKeyLabelParamsFromUrlScheme(String keyLabel) {
        String keyLabelData = fromDataUrlScheme(keyLabel);

        return convertStringToKeyLabelParamsMap(keyLabelData);
    }

    /**
     * URL encoding of key label data parameter value
     * @param dataParamValue data parameter value
     * @return url encoded Key Label data parameter value
     */
    public static String urlEncodeValue(String dataParamValue) {
        return URLEncoder.encode(dataParamValue, StandardCharsets.UTF_8);
    }

    /**
     * Create public key label parameters for data section of formatted key label.
     * @param keyLabel label to identify public key from other keys, user-given or generated
     * @param pubKeyFile public key file
     * @return KeyLabelParams key label parameters required for data section
     */
    public static KeyLabelParams createPublicKeyLabelParams(@Nullable String keyLabel, @Nullable File pubKeyFile) {
        KeyLabelParams keyLabelParams = createKeyLabelCommonParams(
            EncryptionKeyOrigin.PUBLIC_KEY, KeyLabelDataVersion.V_1
        );

        if (keyLabel != null) {
            keyLabelParams.addParam(KeyLabelDataFields.LABEL.name(), keyLabel);
        }

        if (isKeyLabelFileNameAllowedToBeAdded() && null != pubKeyFile) {
            keyLabelParams.addParam(KeyLabelDataFields.FILE.name(), pubKeyFile.getName());
        }

        return keyLabelParams;
    }

    /**
     * Create certificate key label parameters for data section of formatted key label.
     * @param keyLabel key label as common name from certificate
     * @param certSha1 certificate sha1 fingerprint
     * @param certFile certificate file
     * @return KeyLabelParams key label parameters required for data section
     */
    public static KeyLabelParams createCertKeyLabelParams(
        String keyLabel, String certSha1, File certFile
    ) {
        KeyLabelParams keyLabelParams = createKeyLabelCommonParams(
            EncryptionKeyOrigin.CERTIFICATE, KeyLabelDataVersion.V_1
        );

        if (isKeyLabelFileNameAllowedToBeAdded() && null != certFile) {
            keyLabelParams.addParam(KeyLabelDataFields.FILE.name(), certFile.getName());
        }

        if (null != keyLabel) {
            keyLabelParams.addParam(KeyLabelDataFields.CN.name(), keyLabel);
        }

        if (null != certSha1) {
            keyLabelParams.addParam(KeyLabelDataFields.CERT_SHA1.name(), certSha1);
        }

        return keyLabelParams;
    }

    /**
     * Create eID key label parameters for data section of formatted key label.
     * @param keyLabel key label as common name from certificate
     * @param serialNumber serial number from LDAP server
     * @return KeyLabelParams key label parameters required for data section
     */
    public static KeyLabelParams createEIdKeyLabelParams(
        String keyLabel, BigInteger serialNumber
    ) {
        KeyLabelParams keyLabelParams = createKeyLabelCommonParams(
            EncryptionKeyOrigin.ID_CARD, KeyLabelDataVersion.V_1
        );
        keyLabelParams.addParam(KeyLabelDataFields.CN.name(), keyLabel);
        keyLabelParams.addParam(KeyLabelDataFields.SERIAL_NUMBER.name(), String.valueOf(serialNumber));

        int endAfterLastName = keyLabel.indexOf(",");
        int endAfterFirstName = keyLabel.indexOf(",", endAfterLastName + 1);

        keyLabelParams.addParam(
            KeyLabelDataFields.FIRST_NAME.name(),
            keyLabel.substring(endAfterLastName + 1, endAfterFirstName)
        );

        keyLabelParams.addParam(
            KeyLabelDataFields.LAST_NAME.name(),
            keyLabel.substring(0, endAfterLastName)
        );

        return keyLabelParams;
    }

    /**
     * Create symmetric key label parameters for data section of formatted key label.
     * @param encryptionKeyOrigin encryption key origin
     * @param keyLabel key label to identify password or secret from others, user-given or generated
     * @return KeyLabelParams key label parameters required for data section
     */
    public static KeyLabelParams createSymmetricKeyLabelParams(
        EncryptionKeyOrigin encryptionKeyOrigin,
        String keyLabel
    ) {
        KeyLabelParams keyLabelParams = createKeyLabelCommonParams(
            encryptionKeyOrigin, KeyLabelDataVersion.V_1
        );
        keyLabelParams.addParam(KeyLabelDataFields.LABEL.name(), keyLabel);

        return keyLabelParams;
    }

    /**
     * Create secret key label parameters for data section of formatted key label
     * @param keyLabel key label to identify symmetric key from other keys, user-given or generated
     * @return KeyLabelParams key label parameters required for data section
     */
    public static KeyLabelParams createSecretKeyLabelParams(String keyLabel) {
        KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
            EncryptionKeyOrigin.SECRET, keyLabel
        );
        //ToDo add correct file, not payload file RM-3648
//        if (isKeyLabelFileNameAllowedToBeAdded()) {
//            keyLabelParams.addParam(KeyLabelDataFields.FILE.name(), payloadFileName);
//        }

        return keyLabelParams;
    }

    /**
     * Create key label parameters of key shares for data section of formatted key label.
     * @param keyLabel key label as (National) personal number
     * @return KeyLabelParams key label parameters required for data section
     */
    public static KeyLabelParams createKeySharesKeyLabelParams(String keyLabel) {
        KeyLabelParams keyLabelParams = createKeyLabelCommonParams(
            EncryptionKeyOrigin.KEY_SHARE, KeyLabelTools.KeyLabelDataVersion.V_2
        );
        keyLabelParams.addParam(KeyLabelDataFields.PNO.name(), keyLabel);

        return keyLabelParams;
    }

    /**
     * Prepares map of key label parameters into readable string.
     * @param keyLabelParamsMap map of key label parameters
     * @return string of key label parameters
     */
    public static String keyLabelParamsForDisplaying(Map<String, String> keyLabelParamsMap) {
        return keyLabelParamsMap.keySet().stream()
            .map(key -> key + ":" + keyLabelParamsMap.get(key))
            .collect(Collectors.joining(", "));
    }

    private static KeyLabelParams createKeyLabelCommonParams(
        EncryptionKeyOrigin encryptionKeyOrigin,
        KeyLabelTools.KeyLabelDataVersion version
    ) {
        Map<String, String> keyLabelParams = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        keyLabelParams.put(
            KeyLabelDataFields.V.name(),
            urlEncodeValue(toNumbericString(version))
        );
        KeyLabelType type = getKeyLabelType(encryptionKeyOrigin);
        keyLabelParams.put(
            KeyLabelDataFields.TYPE.name(),
            urlEncodeValue(KeyLabelType.ofType(type))
        );

        return new KeyLabelParams(encryptionKeyOrigin, keyLabelParams);
    }

    public static KeyLabelType getKeyLabelType(EncryptionKeyOrigin encryptionKeyOrigin) {
        switch (encryptionKeyOrigin) {
            case CERTIFICATE -> {
                return KeyLabelType.CERT;
            }
            case ID_CARD -> {
                return KeyLabelType.ID_CARD;
            }
            case KEY_SHARE -> {
                return KeyLabelType.AUTH;
            }
            case PASSWORD -> {
                return KeyLabelType.PW;
            }
            case PUBLIC_KEY -> {
                return KeyLabelType.PUB_KEY;
            }
            case SECRET -> {
                return KeyLabelType.SECRET;
            }
            default -> throw new IllegalArgumentException("Wrong key label origin");
        }
    }

    private static String extractKeyLabelFromParams(Map<String, String> keyLabelParams) {
        KeyLabelType keyLabelType
            = KeyLabelType.fromParams(keyLabelParams.get(KeyLabelDataFields.TYPE.name()));
        return extractKeyLabelByType(keyLabelType, keyLabelParams);
    }

    private static String extractKeyLabelByType(
        KeyLabelType keyLabelType,
        Map<String, String> keyLabelParams
    ) {
        switch (keyLabelType) {
            case AUTH -> {
                return keyLabelParams.get(KeyLabelDataFields.PNO.name());
            }
            case PW, SECRET -> {
                return keyLabelParams.get(KeyLabelDataFields.LABEL.name());
            }
            case PUB_KEY -> {
                return null;
            }
            default -> throw new IllegalArgumentException("Wrong key label type");
        }
    }

    /**
     * Converts key label into data URL scheme.
     * @param data key label data
     * @return data URL scheme String
     */
    public static String toDataUrlScheme(String data) {
        StringBuilder sb = new StringBuilder();
        sb.append(DATA);

        if (isBase64Encoded(data)) {
            sb.append(BASE_64_DELIMITER + "base64");
        }
        sb.append(DATA_DELIMITER);
        sb.append(data);

        return sb.toString();
    }

    /**
     * Extracts key label from data URL scheme.
     * @param dataUrlScheme data URL scheme String
     * @return key label data
     */
    private static String fromDataUrlScheme(String dataUrlScheme) {
        String dataAfterSemicolon = StringUtils.substringAfter(dataUrlScheme, BASE_64_DELIMITER);
        if (!dataAfterSemicolon.isEmpty()) {
            return decodeFromBase64(dataAfterSemicolon);
        }

        String dataAfterComma = StringUtils.substringAfter(dataUrlScheme, DATA_DELIMITER);
        if (!dataAfterComma.isEmpty()) {
            return dataAfterComma;
        }

        return StringUtils.substringAfter(dataUrlScheme, ":");
    }

    private static boolean keyLabelIsFormatted(Object keyLabel) {
        return keyLabel.toString().contains(DATA);
    }

    public static boolean isFormatted(String keyLabel) {
        if (keyLabel == null) {
            return false;
        }

        return  keyLabel.startsWith(DATA);
    }

    private static String decodeFromBase64(String data) {
        if (data.contains("base64")) {
            String dataAfterDelimiter = StringUtils.substringAfter(data, DATA_DELIMITER);
            if (isBase64Encoded(dataAfterDelimiter)) {
                return new String(Base64.getDecoder().decode(dataAfterDelimiter));
            }
            return dataAfterDelimiter;
        }
        return data;
    }

    public static String urlDecodeValue(String encodedDataFieldValue) {
        return URLDecoder.decode(encodedDataFieldValue, StandardCharsets.UTF_8);
    }

    private static boolean isBase64Encoded(String data) {
        return BASE64_PATTERN.matcher(data).matches();
    }

    public static String convertKeyLabelParamsMapToString(Map<String, String> map) {
        return map.keySet().stream()
            .map(key -> key + DATA_PARAMETERS_KEY_VALUE_DELIMITER + map.get(key))
            .collect(Collectors.joining(DATA_PARAMETERS_DELIMITER));
    }

    private static Map<String, String> convertStringToKeyLabelParamsMap(String data) {
        Map<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (data.isBlank()) {
            return result;
        }
        String[] parts = data.split(DATA_PARAMETERS_DELIMITER);


        for (String keyValue : parts) {
            String[] params = keyValue.split(DATA_PARAMETERS_KEY_VALUE_DELIMITER);
            result.put(params[0], urlDecodeValue(params[1]));
        }

        return result;
    }

    /**
     * The list of possible key label data fields according to the authentication type
     */
    public enum KeyLabelDataFields {
        CERT_SHA1,
        CN,
        FILE,
        FIRST_NAME,
        LABEL,
        LAST_NAME,
        PNO, // for Smart id & Mobile id
        SERIAL_NUMBER,
        TYPE,
        V
    }

    /**
     * Key label data types
     */
    public enum KeyLabelType {
        AUTH,
        CERT,
        ID_CARD,
        PUB_KEY,
        PW,
        SECRET;

        public static String ofType(KeyLabelType type) {
            return type.name().toLowerCase(Locale.ROOT);
        }

        public static KeyLabelType fromParams(String type) {
            return KeyLabelType.getName(type);
        }

        public static KeyLabelType getName(String keyLabelType) {
            for (var type : KeyLabelType.values()) {
                if (null != keyLabelType && type.name().compareToIgnoreCase(keyLabelType) == 0) {
                    return type;
                }
            }

            return null;
        }
    }

    /**
     * Key label data version
     */
    public enum KeyLabelDataVersion {
        V_1,
        V_2;

        public static String toNumbericString(KeyLabelDataVersion v) {
            switch (v) {
                case V_1 -> {
                    return "1";
                }
                case V_2 -> {
                    return "2";
                }
                default -> throw new IllegalStateException("Unexpected key label data version: " + v);
            }
        }
    }

}
