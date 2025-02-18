package ee.cyber.cdoc2;

import java.util.Map;
import java.util.Properties;

import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.MobileIdClientConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_SHARES_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.MOBILE_ID_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.SMART_ID_PROPERTIES;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;

public final class ClientConfigurationUtil {

    public static final String MOBILE_ID_PROPERTIES_PATH = "mobile-id/mobile_id-test.properties";
    public static final String SMART_ID_PROPERTIES_PATH = "smart-id/smart_id-test.properties";

    // contains demo env properties used in tests
    // "smart-id.properties"="classpath:smart-id/smart_id-test.properties"
    public static final Properties DEMO_ENV_PROPERTIES = Map.of(
            SMART_ID_PROPERTIES, CLASSPATH + SMART_ID_PROPERTIES_PATH,
            MOBILE_ID_PROPERTIES, CLASSPATH + MOBILE_ID_PROPERTIES_PATH
    )
        .entrySet().stream()
        .collect(Properties::new,
            (props, entry) -> props.setProperty(entry.getKey(), entry.getValue()),
            Map::putAll);

    public static final Properties TEST_ENV_PROPERTIES = Map.of(
        KEY_SHARES_PROPERTIES, CLASSPATH + "key_shares-test.properties"
    )
        .entrySet().stream()
        .collect(Properties::new,
            (props, entry) -> props.setProperty(entry.getKey(), entry.getValue()),
            Map::putAll);


    private ClientConfigurationUtil() { }

    public static SmartIdClientConfiguration getSmartIdDemoEnvConfiguration() throws ConfigurationLoadingException {

        return SmartIdClientConfiguration.load(PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(SMART_ID_PROPERTIES)));
    }

    public static MobileIdClientConfiguration getMobileIdDemoEnvConfiguration() throws ConfigurationLoadingException {
        Properties properties = PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(MOBILE_ID_PROPERTIES));
        return MobileIdClientConfiguration.load(properties);
    }

    public static KeySharesConfiguration initKeySharesTestEnvConfiguration() throws ConfigurationLoadingException {
        Properties properties = PropertiesLoader.loadProperties(
            TEST_ENV_PROPERTIES.getProperty(KEY_SHARES_PROPERTIES));
        return KeySharesConfiguration.load(properties);
    }

}
