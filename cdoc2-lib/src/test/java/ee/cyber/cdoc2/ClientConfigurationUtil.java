package ee.cyber.cdoc2;

import java.util.Properties;

import ee.cyber.cdoc2.config.CDoc2ConfigurationProvider;
import ee.cyber.cdoc2.config.Cdoc2Configuration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfigurationImpl;
import ee.cyber.cdoc2.config.MobileIdClientConfiguration;
import ee.cyber.cdoc2.config.MobileIdClientConfigurationImpl;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfigurationImpl;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;


public final class ClientConfigurationUtil {

    public static final String SMART_ID_PROPERTIES_PATH = "smart-id/smart_id-test.properties";

    private ClientConfigurationUtil() { }

    public static SmartIdClientConfiguration getSmartIdConfiguration() throws ConfigurationLoadingException {
        Properties properties = loadProperties(
            CLASSPATH + SMART_ID_PROPERTIES_PATH
        );
        Cdoc2Configuration configuration = new SmartIdClientConfigurationImpl(properties);

        return CDoc2ConfigurationProvider.initSmartIdClientConfig(configuration);
    }

    public static SmartIdClientConfiguration registerFromProperties(Properties properties) {
        Cdoc2Configuration configuration = new SmartIdClientConfigurationImpl(properties);

        return CDoc2ConfigurationProvider.initSmartIdClientConfig(configuration);
    }

    public static MobileIdClientConfiguration getMobileIdConfiguration() throws ConfigurationLoadingException {
        Properties properties = loadProperties(
            CLASSPATH + "mobile-id/mobile_id-test.properties"
        );
        Cdoc2Configuration configuration = new MobileIdClientConfigurationImpl(properties);

        return CDoc2ConfigurationProvider.initMobileIdClientConfig(configuration);
    }

    public static KeySharesConfiguration initKeySharesConfiguration() throws ConfigurationLoadingException {
        Properties properties = loadProperties(
            CLASSPATH + "key_shares-test.properties"
        );
        Cdoc2Configuration configuration = new KeySharesConfigurationImpl(properties);

        return CDoc2ConfigurationProvider.initKeyShareClientConfig(configuration);
    }

}
