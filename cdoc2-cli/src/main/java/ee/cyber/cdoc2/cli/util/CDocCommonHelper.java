package ee.cyber.cdoc2.cli.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import ee.cyber.cdoc2.client.ExternalService;
import ee.cyber.cdoc2.client.ExternalServiceImpl;
import ee.cyber.cdoc2.config.CDoc2ConfigurationProvider;
import ee.cyber.cdoc2.config.Cdoc2Configuration;
import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.KeyCapsuleClientConfigurationImpl;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfigurationImpl;
import ee.cyber.cdoc2.config.MobileIdClientConfigurationImpl;
import ee.cyber.cdoc2.config.SmartIdClientConfigurationImpl;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_SHARES_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.MOBILE_ID_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.SMART_ID_PROPERTIES;
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

    public static ExternalService initKeyShareClientFactory() throws GeneralSecurityException {
        ExternalServiceImpl clientFactory = new ExternalServiceImpl();
        return clientFactory.initKeyShareClientFactory(loadKeySharesConfiguration());
    }

    public static ExternalService getKeyCapsulesClientFactory(
        String keyServerPropertiesFile
    ) throws GeneralSecurityException, IOException, ConfigurationLoadingException {
        Properties p = CDocCommonHelper.getServerProperties(keyServerPropertiesFile);

        return initKeyCapsuleClientFactory(p);
    }

    private static ExternalService initKeyCapsuleClientFactory(Properties p)
        throws GeneralSecurityException {

        ExternalServiceImpl clientFactory = new ExternalServiceImpl();
        return clientFactory.initKeyCapsuleClientFactory(initializeCapsuleConfiguration(p));
    }

    private static KeyCapsuleClientConfiguration initializeCapsuleConfiguration(Properties p) {
        Cdoc2Configuration configuration = new KeyCapsuleClientConfigurationImpl(p);
        CDoc2ConfigurationProvider.initKeyCapsuleClientConfig(configuration);
        return configuration.keyCapsuleClientConfiguration();
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

    static void loadSmartIdConfiguration() throws ConfigurationLoadingException {
        String propertiesFilePath = System.getProperty(
            SMART_ID_PROPERTIES,
            "config/smart-id/" + SMART_ID_PROPERTIES
        );
        if (null == propertiesFilePath) {
            throw new ConfigurationLoadingException("Smart ID configuration property is missing");
        }
        Properties properties = loadProperties(propertiesFilePath);
        Cdoc2Configuration configuration = new SmartIdClientConfigurationImpl(properties);

        CDoc2ConfigurationProvider.initSmartIdClientConfig(configuration);
    }

    static void loadMobileIdConfiguration() throws ConfigurationLoadingException {
        String propertiesFilePath = System.getProperty(
            MOBILE_ID_PROPERTIES,
            "config/mobile-id/" + MOBILE_ID_PROPERTIES
        );
        if (null == propertiesFilePath) {
            throw new ConfigurationLoadingException("Mobile ID configuration property is missing");
        }
        Properties properties = loadProperties(propertiesFilePath);
        Cdoc2Configuration configuration = new MobileIdClientConfigurationImpl(properties);

        CDoc2ConfigurationProvider.initMobileIdClientConfig(configuration);
    }

}
