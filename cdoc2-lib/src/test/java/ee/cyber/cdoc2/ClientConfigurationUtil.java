package ee.cyber.cdoc2;

import java.util.Properties;

import ee.cyber.cdoc2.config.CDoc2ConfigurationProvider;
import ee.cyber.cdoc2.config.Cdoc2Configuration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfigurationImpl;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfigurationImpl;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;


public final class ClientConfigurationUtil {

    private ClientConfigurationUtil() { }

    public static SmartIdClientConfiguration getSmartIdConfiguration() throws ConfigurationLoadingException {
        Properties properties = loadProperties(
            CLASSPATH + "smartid/smart_id-test.properties"
        );
        Cdoc2Configuration configuration = new SmartIdClientConfigurationImpl(properties);
        CDoc2ConfigurationProvider.init(configuration);

        return configuration.smartIdClientConfiguration();
    }

    public static SmartIdClientConfiguration registerFromProperties(Properties properties) {
        Cdoc2Configuration configuration = new SmartIdClientConfigurationImpl(properties);
        CDoc2ConfigurationProvider.init(configuration);

        return configuration.smartIdClientConfiguration();
    }

    public static KeySharesConfiguration initKeySharesConfiguration() throws ConfigurationLoadingException {
        Properties properties = loadProperties(
            CLASSPATH + "key_shares-test.properties"
        );
        Cdoc2Configuration configuration = new KeySharesConfigurationImpl(properties);
        CDoc2ConfigurationProvider.init(configuration);

        return configuration.keySharesConfiguration();
    }

}
