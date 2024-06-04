package ee.cyber.cdoc2.config;

import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


/**
 * Key capsule client configuration properties.
 */
public record ClientConfigurationProperties(
    int keySharesServersNum,
    List<String> keySharesServersUrls,
    int keySharesServersMinNum,
    String keySharesAlgorithm
) {

    private static final Logger log = LoggerFactory.getLogger(ClientConfigurationProperties.class);

    private static final String PROPERTIES_FILE_CLASSPATH = "key-shares.properties";

    private static final String KEY_SHARES_SERVERS_URLS_PROP = "key-shares.servers.urls";
    private static final String KEY_SHARES_SERVERS_MIN_NUM_PROP = "key-shares.servers.min_num";
    private static final String KEY_SHARES_ALGORITHM_PROP = "key-shares.algorithm";

    public static ClientConfigurationProperties load() throws ConfigurationLoadingException {
        log.info("Loading Client configuration from {}", PROPERTIES_FILE_CLASSPATH);
        var properties = loadProperties(PROPERTIES_FILE_CLASSPATH);
        return loadFromProperties(properties);
    }

    public static ClientConfigurationProperties loadFromProperties(Properties properties)
        throws ConfigurationLoadingException {

        var keySharesServersUrls = ConfigurationPropertyUtil.splitString(
            log,
            properties,
            KEY_SHARES_SERVERS_URLS_PROP
        );
        var keySharesServersNum = keySharesServersUrls.size();
        var keySharesServersMinNum = ConfigurationPropertyUtil.getRequiredInteger(
            log,
            properties,
            KEY_SHARES_SERVERS_MIN_NUM_PROP
        );
        var keySharesAlgorithm = getRequiredProperty(properties, KEY_SHARES_ALGORITHM_PROP);
        ConfigurationPropertyUtil.notBlank(
            log,
            keySharesAlgorithm,
            KEY_SHARES_ALGORITHM_PROP
        );

        return new ClientConfigurationProperties(
            keySharesServersNum,
            keySharesServersUrls,
            keySharesServersMinNum,
            keySharesAlgorithm
        );
    }

    public int getKeySharesServersNum() {
        return this.keySharesServersNum;
    }

    public List<String> getKeySharesServersUrls() {
        return this.keySharesServersUrls;
    }

    public int getKeySharesServersMinNum() {
        return this.keySharesServersMinNum;
    }

    public String getKeySharesAlgorithm() {
        return this.keySharesAlgorithm;
    }

}
