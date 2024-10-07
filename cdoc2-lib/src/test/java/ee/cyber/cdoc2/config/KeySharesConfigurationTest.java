package ee.cyber.cdoc2.config;

import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.ClientConfigurationUtil.getKeySharesConfiguration;
import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class KeySharesConfigurationTest {

    private static final int MIN_NUM_OF_SERVERS = 2;

    @Test
    void loadClientConfigurationProperties() throws ConfigurationLoadingException {
        KeySharesConfiguration config = getKeySharesConfiguration();
        assertTrue(config.getKeySharesServersNum() > 0);
        assertEquals(
            List.of("https://server1", "https://server2"),
            config.getKeySharesServersUrls()
        );
        assertEquals(MIN_NUM_OF_SERVERS, config.getKeySharesServersMinNum());
        assertEquals("n-of-n", config.getKeySharesAlgorithm());
    }

    @Test
    void failToLoadClientConfigPropsWithWrongServersQuantity() throws ConfigurationLoadingException {
        Properties properties = getProperties();
        properties.setProperty("key-shares.servers.urls", "https://server1, https://server2");
        properties.setProperty("key-shares.servers.min_num", "3");
        Cdoc2Configuration configuration = initConfiguration(properties);

        assertThrowsConfigurationLoadingException(
            configuration::keySharesConfiguration
        );
    }

    @ParameterizedTest
    @CsvSource({
        KEY_SHARES_ALGORITHM + ",''",
        KEY_SHARES_SERVERS_URLS + ",''",
        KEY_SHARES_SERVERS_MIN_NUM + ",non_numerical",
    })
    void failedToLoadClientConfigurationPropertiesWithInvalidProperty(
        String propKey,
        String propValue
    ) throws ConfigurationLoadingException {

        Properties properties = getProperties();
        properties.setProperty(propKey, propValue);
        Cdoc2Configuration configuration = initConfiguration(properties);

        assertThrowsConfigurationLoadingException(
            configuration::keySharesConfiguration
        );
    }

    private Properties getProperties() throws ConfigurationLoadingException {
        return loadProperties(
            CLASSPATH + "key_shares-test.properties"
        );
    }

    private Cdoc2Configuration initConfiguration(Properties properties) {
        Cdoc2Configuration configuration = new KeySharesConfigurationImpl(properties);
        CDoc2ConfigurationProvider.init(configuration);
        return configuration;
    }

    private void assertThrowsConfigurationLoadingException(Executable validation) {
        assertThrows(ConfigurationLoadingException.class, validation);
    }

}
