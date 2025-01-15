package ee.cyber.cdoc2.cli.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.config.CDoc2ConfigurationProvider;
import ee.cyber.cdoc2.config.Cdoc2Configuration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfigurationImpl;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_SHARES_PROPERTIES;
import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;


/**
 * Helper class for common usage.
 */
public final class CDocCommonHelper {

    private CDocCommonHelper() { }

    public static Properties getServerProperties(String keyServerPropertiesFile) throws IOException {
        Properties p = new Properties();
        p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
        return p;
    }

    public static KeyShareClientFactory initKeyShareClientFactory() throws GeneralSecurityException {
        return KeySharesClientHelper.createFactory(loadKeySharesConfiguration());
    }

    private static KeySharesConfiguration loadKeySharesConfiguration() {
        String propertiesFilePath = System.getProperty(
            KEY_SHARES_PROPERTIES,
            "config/localhost/" + KEY_SHARES_PROPERTIES
        );
        if (null == propertiesFilePath) {
            throw new ConfigurationLoadingException("Key Shares configuration property is missing");
        }

        Properties properties = loadProperties(propertiesFilePath);
        Cdoc2Configuration configuration = new KeySharesConfigurationImpl(properties);
        CDoc2ConfigurationProvider.initKeyShareClientConfig(configuration);

        return configuration.keySharesConfiguration();
    }
}
