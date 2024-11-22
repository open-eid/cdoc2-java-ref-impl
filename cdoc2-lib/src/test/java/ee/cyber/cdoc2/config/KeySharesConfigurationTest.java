package ee.cyber.cdoc2.config;

import java.util.Properties;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.ClientConfigurationUtil.initKeySharesConfiguration;
import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.Resources.CLASSPATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class KeySharesConfigurationTest {

    private static final int MIN_NUM_OF_SERVERS = 2;

    @Test
    void loadClientConfigurationProperties() throws ConfigurationLoadingException {
        KeySharesConfiguration config = initKeySharesConfiguration();
        assertTrue(config.getKeySharesServersNum() > 0);
        assertEquals(
            Set.of("https://localhost:8442", "https://localhost:8443"),
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

        assertThrowsConfigurationLoadingException(
            () -> initConfiguration(properties)
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

        assertThrowsConfigurationLoadingException(
            () -> initConfiguration(properties)
        );
    }

    private Properties getProperties() throws ConfigurationLoadingException {
        return loadProperties(
            CLASSPATH + "key_shares-test.properties"
        );
    }

    private KeySharesConfiguration initConfiguration(Properties properties)
        throws ConfigurationLoadingException {

        Cdoc2Configuration configuration = new KeySharesConfigurationImpl(properties);

        return CDoc2ConfigurationProvider.initKeyShareClientConfig(configuration);
    }

    private void assertThrowsConfigurationLoadingException(Executable validation) {
        assertThrows(ConfigurationLoadingException.class, validation);
    }

}
