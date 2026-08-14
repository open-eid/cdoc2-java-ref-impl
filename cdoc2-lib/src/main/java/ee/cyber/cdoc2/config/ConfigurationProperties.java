package ee.cyber.cdoc2.config;


/**
 * CDOC2 configuration properties
 */
public final class ConfigurationProperties {

    private ConfigurationProperties() {
    }

    /**
     * Defines key-capsules server properties file location and initializes mTLS, initialize KeyCapsuleClientFactory
     * may ask for PIN, when private key is on smart-card
     */
    public static final String KEY_CAPSULE_PROPERTIES = "key-capsule.properties";

    /**
     * Initialize KeyCapsuleClient only that doesn't require mTLS
     */
    public static final String KEY_CAPSULE_POST_PROPERTIES = "key-capsule-post.properties";

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

    /**
     * Key label file name field
     */
    public static final String KEY_LABEL_FILE_NAME_PROPERTY
        = "ee.cyber.cdoc2.key-label.file-name.added";
    // added by default
    public static final boolean KEY_LABEL_FILE_NAME_ADDED_DEFAULT = true;

    /**
     * Key label machine-readable format is enabled
     */
    public static final String KEY_LABEL_FORMAT_PROPERTY
        = "ee.cyber.cdoc2.key-label.machine-readable-format.enabled";
    // enabled by default
    public static final boolean KEY_LABEL_FORMAT_ENABLED_DEFAULT = true;

    /**
     * Defines key-shares server properties file location. Used for auth based (Smart-ID/Mobile-ID)
     * encryption/decryption
     **/
    public static final String KEY_SHARES_PROPERTIES = "key-shares.properties";
    public static final String KEY_SHARES_SERVERS_URLS = "key-shares.servers.urls";
    public static final String KEY_SHARES_SERVERS_MIN_NUM = "key-shares.servers.min_num";
    public static final String KEY_SHARES_ALGORITHM = "key-shares.algorithm";
    public static final String KEY_SHARES_CLIENT_TRUST_STORE
        = "cdoc2.key-shares.client.ssl.trust-store";
    public static final String KEY_SHARES_CLIENT_TRUST_STORE_PWD
        = "cdoc2.key-shares.client.ssl.trust-store-password";
    public static final String KEY_SHARES_CLIENT_READ_TIMEOUT
        = "key-shares.client.read-timeout";
    public static final String KEY_SHARES_CLIENT_CONNECT_TIMEOUT
        = "key-shares.client.connect-timeout";
    public static final String KEY_SHARES_CLIENT_TRUST_STORE_TYPE
        = "cdoc2.key-shares.client.ssl.trust-store.type";

    /**
     * If files overwrite is allowed
     */
    public static final String OVERWRITE_PROPERTY = "ee.cyber.cdoc2.overwrite";
    // by default files overwrite is not allowed
    public static final boolean OVERWRITE_DEFAULT = false;

    public static final String PKCS11_CONF_FILE = "cdoc2.pkcs11.conf-file";

    /**
     * Overwrite PKCS11 library location e.g /usr/local/lib/opensc-pkcs11.so
     */
    public static final String PKCS11_LIBRARY_PROPERTY = "pkcs11-library";

    /**
     * Provider name that provides KeyStore.PKCS11, usually SunPKCS11-...
     */
    public static final String PKCS11_PROVIDER_SYSTEM_PROPERTY = "ee.cyber.cdoc2.pkcs11.name";

    /**
     * The slot to use with pkcs11 provider, if not set, then the default of 0 is used
     */
    public static final String PKCS11_SLOT = "ee.cyber.cdoc2.pkcs11.slot";

    /**
     * The key alias to choose the key form pkcs11 keystore, if not set, then the first key is used
     */
    public static final String PKCS11_ALIAS = "ee.cyber.cdoc2.pkcs11.alias";

    /**
     * Defines CDOC2 Authentication Server client properties file location
     */
    public static final String AUTH_SERVER_PROPERTIES = "auth-server.properties";
    public static final String AUTH_SERVER_CLIENT_HOST_URL = "auth-server.client.hostUrl";
    public static final String AUTH_SERVER_CLIENT_TRUST_STORE =
        "auth-server.client.ssl.trust-store";
    public static final String AUTH_SERVER_CLIENT_TRUST_STORE_PWD
        = "auth-server.client.ssl.trust-store-password";
    public static final String AUTH_SERVER_CLIENT_READ_TIMEOUT = "auth-server.client.read-timeout";
    public static final String AUTH_SERVER_CLIENT_CONNECT_TIMEOUT =
        "auth-server.client.connect-timeout";
    public static final String AUTH_SERVER_CLIENT_POLLING_INTERVAL_MS =
        "auth-server.client.polling.intervalMs";
    public static final String AUTH_SERVER_CLIENT_POLLING_MAX_COUNT =
        "auth-server.client.polling.maxCount";

    /**
     * Defines CDOC2 RP Server properties file location
     */
    public static final String RP_SERVER_PROPERTIES = "rp-server.properties";
    public static final String RP_SERVER_CLIENT_HOST_URL = "rp-server.client.hostUrl";
    public static final String RP_SERVER_CLIENT_CERT_LEVEL = "rp-server.client.certificateLevel";
    public static final String RP_SERVER_CLIENT_TRUST_STORE = "rp-server.client.ssl.trust-store";
    public static final String RP_SERVER_CLIENT_TRUST_STORE_PWD
        = "rp-server.client.ssl.trust-store-password";
    public static final String RP_SERVER_CLIENT_READ_TIMEOUT = "rp-server.client.read-timeout";
    public static final String RP_SERVER_CLIENT_CONNECT_TIMEOUT =
        "rp-server.client.connect-timeout";

    public static final String RP_SERVER_MID_DISPLAY_TEXT_FORMAT
        = "rp-server.mid.display-text-format";
    public static final String RP_SERVER_MID_LANGUAGE
        = "rp-server.mid.language";

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
}
