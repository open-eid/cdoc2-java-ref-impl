package ee.cyber.cdoc20;

public final class CDocConfiguration {
    private CDocConfiguration() {
    }
    /** Overwrite openSC library location eg /usr/local/lib/opensc-pkcs11.so */
    public static final String OPENSC_LIBRARY_PROPERTY = "opensclibrary";

    /** Provider name that provides KeyStore.PKCS11 ,usually SunPKCS11-...*/
    public static final String PKCS11_PROVIDER_SYSTEM_PROPERTY = "ee.cyber.cdoc20.pkcs11.name";

    /** If files are overwritten when decrypting*/
    public static final String OVERWRITE_PROPERTY = "ee.cyber.cdoc20.overwrite";


    //-Dsun.java2d.uiScale=2.0
}
