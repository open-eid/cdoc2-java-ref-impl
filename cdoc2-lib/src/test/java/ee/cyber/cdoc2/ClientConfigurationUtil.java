package ee.cyber.cdoc2;

import java.util.Map;
import java.util.Properties;

import ee.cyber.cdoc2.config.Cdoc2AuthClientConfiguration;
import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.MobileIdClientConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;

public final class ClientConfigurationUtil {

    public static final String MOBILE_ID_PROPERTIES_PATH = "mobile-id/mobile_id-test.properties";
    public static final String AUTH_SERVER_PROPERTIES_PATH = "auth-server/auth_server-test.properties";
    public static final String RP_SERVER_PROPERTIES_PATH = "rp-server/rp_server-test.properties";

    // contains demo env properties used in tests
    // "rp-server.properties"="classpath:rp-server/rp_server-test.properties"
    public static final Properties DEMO_ENV_PROPERTIES = Map.of(
            MOBILE_ID_PROPERTIES, CLASSPATH + MOBILE_ID_PROPERTIES_PATH,
            AUTH_SERVER_PROPERTIES, CLASSPATH + AUTH_SERVER_PROPERTIES_PATH,
            RP_SERVER_PROPERTIES, CLASSPATH + RP_SERVER_PROPERTIES_PATH
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


    private ClientConfigurationUtil() {
    }

    public static Cdoc2RpClientConfiguration getCdoc2RpClientDemoEnvConfiguration()
        throws ConfigurationLoadingException {

        return Cdoc2RpClientConfiguration.load(PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(RP_SERVER_PROPERTIES)));
    }

    public static MobileIdClientConfiguration getMobileIdDemoEnvConfiguration() throws ConfigurationLoadingException {
        Properties properties = PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(MOBILE_ID_PROPERTIES));
        return MobileIdClientConfiguration.load(properties);
    }

    public static Cdoc2AuthClientConfiguration getCdoc2AuthClientConfiguration() throws ConfigurationLoadingException {
        return Cdoc2AuthClientConfiguration.load(PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(AUTH_SERVER_PROPERTIES)
        ));
    }

    public static KeySharesConfiguration initKeySharesTestEnvConfiguration() throws ConfigurationLoadingException {
        Properties properties = PropertiesLoader.loadProperties(
            TEST_ENV_PROPERTIES.getProperty(KEY_SHARES_PROPERTIES));
        return KeySharesConfiguration.load(properties);
    }

}
