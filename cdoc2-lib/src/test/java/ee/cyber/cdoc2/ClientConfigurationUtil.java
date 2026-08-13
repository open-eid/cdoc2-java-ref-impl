package ee.cyber.cdoc2;

import java.util.Map;
import java.util.Properties;

import ee.cyber.cdoc2.config.AuthClientConfiguration;
import ee.cyber.cdoc2.config.RpClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;

public final class ClientConfigurationUtil {
    public static final String AUTH_SERVER_PROPERTIES_PATH = "auth-server/auth_server-test.properties";
    public static final String RP_SERVER_PROPERTIES_PATH = "rp-server/rp_server-test.properties";

    // contains demo env properties used in tests
    // "rp-server.properties"="classpath:rp-server/rp_server-test.properties"
    public static final Properties DEMO_ENV_PROPERTIES = Map.of(
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

    public static RpClientConfiguration getCdoc2RpClientDemoEnvConfiguration()
        throws ConfigurationLoadingException {

        return RpClientConfiguration.load(PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(RP_SERVER_PROPERTIES)));
    }

    public static AuthClientConfiguration getCdoc2AuthClientConfiguration() {
        return getCdoc2AuthClientConfiguration(Map.of());
    }

    public static AuthClientConfiguration getCdoc2AuthClientConfiguration(
        Map<String, String> propOverrides) throws ConfigurationLoadingException {

        Properties properties = PropertiesLoader.loadProperties(
            DEMO_ENV_PROPERTIES.getProperty(AUTH_SERVER_PROPERTIES)
        );

        properties.putAll(propOverrides);

        return AuthClientConfiguration.load(properties);
    }

    public static KeySharesConfiguration initKeySharesTestEnvConfiguration() throws ConfigurationLoadingException {
        Properties properties = PropertiesLoader.loadProperties(
            TEST_ENV_PROPERTIES.getProperty(KEY_SHARES_PROPERTIES));
        return KeySharesConfiguration.load(properties);
    }

}
