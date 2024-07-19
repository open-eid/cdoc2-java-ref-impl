package ee.cyber.cdoc2;


public final class CDocConfiguration {

    private CDocConfiguration() {
    }

    /** Overwrite PKCS11 library location e.g /usr/local/lib/opensc-pkcs11.so */
    public static final String PKCS11_LIBRARY_PROPERTY = "pkcs11-library";

    /** Provider name that provides KeyStore.PKCS11, usually SunPKCS11-...*/
    public static final String PKCS11_PROVIDER_SYSTEM_PROPERTY = "ee.cyber.cdoc2.pkcs11.name";

    /** If files overwrite is allowed */
    public static final String OVERWRITE_PROPERTY = "ee.cyber.cdoc2.overwrite";
    // by default files overwrite is not allowed
    public static final boolean DEFAULT_OVERWRITE = false;

    /** Key label machine-readable format is enabled */
    public static final String KEY_LABEL_FORMAT_PROPERTY
        = "ee.cyber.cdoc2.key-label.machine-readable-format.enabled";
    // enabled by default
    public static final boolean DEFAULT_KEY_LABEL_FORMAT_ENABLED = true;

    /** Key label file name field */
    public static final String KEY_LABEL_FILE_NAME_PROPERTY
        = "ee.cyber.cdoc2.key-label.file-name.added";
    // added by default
    public static final boolean DEFAULT_KEY_LABEL_FILE_NAME_ADDED = true;

    public static final String TAR_ENTRIES_THRESHOLD_PROPERTY = "ee.cyber.cdoc2.tarEntriesThreshold";

    public static final String GZIP_COMPRESSION_THRESHOLD_PROPERTY = "ee.cyber.cdoc2.compressionThreshold";

    public static final String DISK_USAGE_THRESHOLD_PROPERTY = "ee.cyber.cdoc2.maxDiskUsagePercentage";

    public static boolean isOverWriteAllowed() {
        return parseBooleanProperty(DEFAULT_OVERWRITE, OVERWRITE_PROPERTY);
    }

    public static boolean isKeyLabelMachineReadableFormatEnabled() {
        return parseBooleanProperty(DEFAULT_KEY_LABEL_FORMAT_ENABLED, KEY_LABEL_FORMAT_PROPERTY);
    }

    public static boolean isKeyLabelFileNameAllowedToBeAdded() {
        return parseBooleanProperty(DEFAULT_KEY_LABEL_FILE_NAME_ADDED, KEY_LABEL_FILE_NAME_PROPERTY);
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
