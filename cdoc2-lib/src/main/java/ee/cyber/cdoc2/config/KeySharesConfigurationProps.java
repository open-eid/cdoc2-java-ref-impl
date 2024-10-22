package ee.cyber.cdoc2.config;

import java.util.Properties;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


/**
 * Key shares client configuration properties.
 *
 * @param keySharesServersNum number of key shares servers
 * @param keySharesServersUrls key shares servers URL-s
 * @param keySharesServersMinNum minimum quantity of key shares servers
 * @param keySharesAlgorithm key shares algorithm
 * @param clientTrustStore client trust store
 * @param clientTrustStoreType client trust store type
 * @param clientTrustStorePw client trust store password
 */
public record KeySharesConfigurationProps(
    int keySharesServersNum,
    Set<String> keySharesServersUrls,
    int keySharesServersMinNum,
    String keySharesAlgorithm,
    String clientTrustStore,
    String clientTrustStoreType,
    String clientTrustStorePw
) implements KeySharesConfiguration {

    private static final Logger log = LoggerFactory.getLogger(KeySharesConfigurationProps.class);

    public static KeySharesConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading Key Shares configuration for Key Capsule client.");

        var keySharesServersUrls = ConfigurationPropertyUtil.splitString(
            log,
            properties,
            KEY_SHARES_SERVERS_URLS
        );

        var keySharesServersNum = keySharesServersUrls.size();
        int keySharesServersMinNum = ConfigurationPropertyUtil.getRequiredInteger(
            log,
            properties,
            KEY_SHARES_SERVERS_MIN_NUM
        );
        validateServersMinQuantity(keySharesServersNum, keySharesServersMinNum);

        var keySharesAlgorithm = getRequiredProperty(properties, KEY_SHARES_ALGORITHM);
        ConfigurationPropertyUtil.notBlank(
            log,
            keySharesAlgorithm,
            KEY_SHARES_ALGORITHM
        );

        var clientTrustStore = properties.getProperty(CLIENT_TRUST_STORE);
        var clientTrustStoreType = properties.getProperty(CLIENT_TRUST_STORE_TYPE, "JKS");
        var clientTrustStorePw = properties.getProperty(CLIENT_TRUST_STORE_PWD);

        return new KeySharesConfigurationProps(
            keySharesServersNum,
            keySharesServersUrls,
            keySharesServersMinNum,
            keySharesAlgorithm,
            clientTrustStore,
            clientTrustStoreType,
            clientTrustStorePw
        );
    }

    private static void validateServersMinQuantity(
        int keySharesServersNum,
        int keySharesServersMinNum
    ) throws ConfigurationLoadingException {

        if (keySharesServersNum < keySharesServersMinNum) {
            String errorMsg = "Key shares servers quantity " + keySharesServersNum
                + " cannot be less than required minimum " + keySharesServersMinNum;
            log.error(errorMsg);
            throw new ConfigurationLoadingException(errorMsg);
        }
    }

    @Override
    public int getKeySharesServersNum() {
        return keySharesServersNum;
    }

    @Override
    public Set<String> getKeySharesServersUrls() {
        return keySharesServersUrls;
    }

    @Override
    public int getKeySharesServersMinNum() {
        return keySharesServersMinNum;
    }

    @Override
    public String getKeySharesAlgorithm() {
        return keySharesAlgorithm;
    }

    @Override
    public String getClientTrustStore() {
        return clientTrustStore;
    }

    @Override
    public String getClientTrustStoreType() {
        return clientTrustStoreType;
    }

    @Override
    public String getClientTrustStorePw() {
        return clientTrustStorePw;
    }

}
