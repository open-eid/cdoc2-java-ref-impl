package ee.cyber.cdoc2.config;


/**
 * Common provider for holding configuration properties.
 */
public final class CDoc2ConfigurationProvider {

    private static Cdoc2Configuration configuration;

    private CDoc2ConfigurationProvider() { }

    public static void init(Cdoc2Configuration cdoc2Configuration) {
        configuration = cdoc2Configuration;
    }

    public static Cdoc2Configuration getConfiguration() {
        return configuration;
    }

}
