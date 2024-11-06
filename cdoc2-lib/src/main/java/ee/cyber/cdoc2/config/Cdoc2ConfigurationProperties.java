package ee.cyber.cdoc2.config;


/**
 * CDOC2 configuration properties
 */
public final class Cdoc2ConfigurationProperties {

    private Cdoc2ConfigurationProperties() { }

    public static final String CLIENT_SERVER_BASE_URL_GET = "cdoc2.client.server.base-url.get";
    public static final String CLIENT_SERVER_BASE_URL_POST = "cdoc2.client.server.base-url.post";
    public static final String CLIENT_SERVER_CONNECT_TIMEOUT = "cdoc2.client.server.connect-timeout";
    public static final String CLIENT_SERVER_DEBUG = "cdoc2.client.server.debug";
    public static final String CLIENT_SERVER_ID = "cdoc2.client.server.id";
    public static final String CLIENT_SERVER_READ_TIMEOUT = "cdoc2.client.server.read-timeout";

    public static final String CLIENT_STORE = "cdoc2.client.ssl.client-store";
    public static final String CLIENT_STORE_PWD = "cdoc2.client.ssl.client-store-password";
    public static final String CLIENT_STORE_PWD_PROMPT
        = "cdoc2.client.ssl.client-store-password.prompt";
    public static final String CLIENT_STORE_TYPE = "cdoc2.client.ssl.client-store.type";
    public static final String CLIENT_TRUST_STORE = "cdoc2.client.ssl.trust-store";
    public static final String CLIENT_TRUST_STORE_PWD = "cdoc2.client.ssl.trust-store-password";
    public static final String CLIENT_TRUST_STORE_TYPE = "cdoc2.client.ssl.trust-store.type";
    public static final String DISK_USAGE_THRESHOLD_PROPERTY = "ee.cyber.cdoc2.maxDiskUsagePercentage";

    public static final String GZIP_COMPRESSION_THRESHOLD_PROPERTY = "ee.cyber.cdoc2.compressionThreshold";

    /** Key label file name field */
    public static final String KEY_LABEL_FILE_NAME_PROPERTY
        = "ee.cyber.cdoc2.key-label.file-name.added";
    // added by default
    public static final boolean KEY_LABEL_FILE_NAME_ADDED_DEFAULT = true;

    /** Key label machine-readable format is enabled */
    public static final String KEY_LABEL_FORMAT_PROPERTY
        = "ee.cyber.cdoc2.key-label.machine-readable-format.enabled";
    // enabled by default
    public static final boolean KEY_LABEL_FORMAT_ENABLED_DEFAULT = true;

    public static final String KEY_SHARES_PROPERTIES = "key-shares.properties";
    public static final String KEY_SHARES_SERVERS_URLS = "key-shares.servers.urls";
    public static final String KEY_SHARES_SERVERS_MIN_NUM = "key-shares.servers.min_num";
    public static final String KEY_SHARES_ALGORITHM = "key-shares.algorithm";
    public static final String KEY_SHARES_NUMBER_OF_SHARES = "key-shares.number_of_shares";
    public static final String KEY_SHARES_MIN_NUMBER_OF_SHARES = "key-shares.min_number_of_shares";
    public static final String KEY_SHARES_CLIENT_TRUST_STORE
        = "cdoc2.key-shares.client.ssl.trust-store";
    public static final String KEY_SHARES_CLIENT_TRUST_STORE_PWD
        = "cdoc2.key-shares.client.ssl.trust-store-password";
    public static final String KEY_SHARES_CLIENT_TRUST_STORE_TYPE
        = "cdoc2.key-shares.client.ssl.trust-store.type";

    /** If files overwrite is allowed */
    public static final String OVERWRITE_PROPERTY = "ee.cyber.cdoc2.overwrite";
    // by default files overwrite is not allowed
    public static final boolean OVERWRITE_DEFAULT = false;

    public static final String PKCS11_CONF_FILE = "cdoc2.pkcs11.conf-file";

    /** Overwrite PKCS11 library location e.g /usr/local/lib/opensc-pkcs11.so */
    public static final String PKCS11_LIBRARY_PROPERTY = "pkcs11-library";

    /** Provider name that provides KeyStore.PKCS11, usually SunPKCS11-...*/
    public static final String PKCS11_PROVIDER_SYSTEM_PROPERTY = "ee.cyber.cdoc2.pkcs11.name";

    public static final String SMART_ID_PROPERTIES = "smart-id.properties";
    public static final String SMART_ID_CLIENT_HOST_URL = "smartid.client.hostUrl";
    public static final String SMART_ID_CLIENT_RELYING_PARTY_UUID
        = "smartid.client.relyingPartyUuid";
    public static final String SMART_ID_CLIENT_RELYING_PARTY_NAME
        = "smartid.client.relyingPartyName";
    public static final String SMART_ID_CLIENT_TRUST_STORE = "smartid.client.ssl.trust-store";
    public static final String SMART_ID_CLIENT_TRUST_STORE_PWD
        = "smartid.client.ssl.trust-store-password";

    public static final String TAR_ENTRIES_THRESHOLD_PROPERTY = "ee.cyber.cdoc2.tarEntriesThreshold";

    public static boolean isOverWriteAllowed() {
        return parseBooleanProperty(OVERWRITE_DEFAULT, OVERWRITE_PROPERTY);
    }

    public static boolean isKeyLabelMachineReadableFormatEnabled() {
        return parseBooleanProperty(KEY_LABEL_FORMAT_ENABLED_DEFAULT, KEY_LABEL_FORMAT_PROPERTY);
    }

    public static boolean isKeyLabelFileNameAllowedToBeAdded() {
        return parseBooleanProperty(KEY_LABEL_FILE_NAME_ADDED_DEFAULT, KEY_LABEL_FILE_NAME_PROPERTY);
    }

    private static boolean parseBooleanProperty(boolean enabled, String propertyName) {
        boolean isEnabled = enabled;
        if (System.getProperties().containsKey(propertyName)) {
            String overwriteStr = System.getProperty(propertyName);

            if (overwriteStr != null) {
                isEnabled = Boolean.parseBoolean(overwriteStr);
            }
        }
        return isEnabled;
    }

    // for running on highDP display
    //-Dsun.java2d.uiScale=2.0
}
