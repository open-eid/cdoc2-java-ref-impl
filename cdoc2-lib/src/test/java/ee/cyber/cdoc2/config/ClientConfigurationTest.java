package ee.cyber.cdoc2.config;

import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class ClientConfigurationTest {

    private static final int MIN_NUM_OF_SERVERS = 2;

    @Test
    void loadClientConfigurationProperties() throws ConfigurationLoadingException {
        ClientConfigurationProperties config = ClientConfigurationProperties
            .loadFromProperties(getProperties());
        assertTrue(config.getKeySharesServersNum() > 0);
        assertEquals(
            List.of("https://server1", "https://server2"),
            config.getKeySharesServersUrls()
        );
        assertEquals(MIN_NUM_OF_SERVERS, config.getKeySharesServersMinNum());
        assertEquals("n-of-n", config.getKeySharesAlgorithm());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "invalid-key_share-servers-min_num.properties",
        "invalid-key_share-algorithm.properties",
        "invalid-key_share-servers.properties"
    })
    void failedToLoadClientConfigurationPropertiesWithInvalidProperty(String fileClasspath)
        throws ConfigurationLoadingException {

        var properties = loadProperties(fileClasspath);
        assertThrows(ConfigurationLoadingException.class, () ->
            ClientConfigurationProperties.loadFromProperties(properties)
        );
    }

    private Properties getProperties() throws ConfigurationLoadingException {
        return loadProperties("key-shares.properties");
    }

}
