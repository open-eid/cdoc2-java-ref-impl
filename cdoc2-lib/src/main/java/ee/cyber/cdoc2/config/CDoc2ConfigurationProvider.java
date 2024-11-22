package ee.cyber.cdoc2.config;


/**
 * Common provider for holding configuration properties.
 */
public final class CDoc2ConfigurationProvider {

    private CDoc2ConfigurationProvider() { }

    public static KeySharesConfiguration initKeyShareClientConfig(Cdoc2Configuration cdoc2Configuration) {
        return cdoc2Configuration.keySharesConfiguration();
    }

    public static SmartIdClientConfiguration initSmartIdClientConfig(Cdoc2Configuration cdoc2Configuration) {
        return cdoc2Configuration.smartIdClientConfiguration();
    }

    public static KeyCapsuleClientConfiguration initKeyCapsuleClientConfig(Cdoc2Configuration cdoc2Configuration) {
        return cdoc2Configuration.keyCapsuleClientConfiguration();
    }

}
