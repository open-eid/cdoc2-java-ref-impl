package ee.cyber.cdoc20;

public final class CDocConfiguration {

    private CDocConfiguration() {
    }
    /** Overwrite PKCS11 library location e.g /usr/local/lib/opensc-pkcs11.so */
    public static final String PKCS11_LIBRARY_PROPERTY = "pkcs11-library";

    /** Provider name that provides KeyStore.PKCS11, usually SunPKCS11-...*/
    public static final String PKCS11_PROVIDER_SYSTEM_PROPERTY = "ee.cyber.cdoc20.pkcs11.name";

    /** If files overwrite is allowed */
    public static final String OVERWRITE_PROPERTY = "ee.cyber.cdoc20.overwrite";

    // by default files overwrite is not allowed
    public static final boolean DEFAULT_OVERWRITE = false;



    public static final String TAR_ENTRIES_THRESHOLD_PROPERTY = "ee.cyber.cdoc20.tarEntriesThreshold";


    public static final String GZIP_COMPRESSION_THRESHOLD_PROPERTY = "ee.cyber.cdoc20.compressionThreshold";


    public static final String DISK_USAGE_THRESHOLD_PROPERTY = "ee.cyber.cdoc20.maxDiskUsagePercentage";

    public static boolean isOverWriteAllowed() {
        boolean overwrite = DEFAULT_OVERWRITE;
        if (System.getProperties().containsKey(OVERWRITE_PROPERTY)) {
            String overwriteStr = System.getProperty(OVERWRITE_PROPERTY);

            if (overwriteStr != null) {
                //only "true" is considered as true
                overwrite = Boolean.parseBoolean(overwriteStr);
            }
        }
        return overwrite;

    }


    // for running on highDP display
    //-Dsun.java2d.uiScale=2.0
}
