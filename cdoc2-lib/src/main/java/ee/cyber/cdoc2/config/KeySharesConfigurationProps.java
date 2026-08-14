package ee.cyber.cdoc2.config;

import java.security.KeyStore;
import java.util.Properties;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.config.ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ApiClientUtil.loadClientTrustKeyStore;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getBoolean;


/**
 * Key shares client configuration properties.
 *
 * @param keySharesServersNum    number of key shares servers
 * @param keySharesServersUrls   key shares servers URL-s
 * @param keySharesServersMinNum minimum quantity of key shares servers
 * @param keySharesAlgorithm     key shares algorithm
 * @param clientTrustStore       client trust store
 * @param readTimeout            read timeout
 * @param connectTimeout         connection timeout
 * @param clientServerDebug      turn on debug logs for client
 */
public record KeySharesConfigurationProps(
    int keySharesServersNum,
    Set<String> keySharesServersUrls,
    int keySharesServersMinNum,
    String keySharesAlgorithm,
    KeyStore clientTrustStore,
    int readTimeout,
    int connectTimeout,
    boolean clientServerDebug
) implements KeySharesConfiguration {
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 500;

    private static final Logger log = LoggerFactory.getLogger(KeySharesConfigurationProps.class);

    public static KeySharesConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading configuration for Key Shares client.");

        var keySharesServersUrls = ConfigurationPropertyUtil.splitString(
            log,
            properties,
            KEY_SHARES_SERVERS_URLS
        );

        int keySharesServersNum = keySharesServersUrls.size();
        int keySharesServersMinNum = ConfigurationPropertyUtil.getRequiredInteger(
            log,
            properties,
            KEY_SHARES_SERVERS_MIN_NUM
        );
        validateServersMinQuantity(keySharesServersNum, keySharesServersMinNum);

        var keySharesAlgorithm = ConfigurationPropertyUtil.getRequiredProperty(properties, KEY_SHARES_ALGORITHM);
        ConfigurationPropertyUtil.notBlank(
            log,
            keySharesAlgorithm,
            KEY_SHARES_ALGORITHM
        );

        var clientTrustStoreFile = properties.getProperty(KEY_SHARES_CLIENT_TRUST_STORE);
        var clientTrustStoreType = properties.getProperty(KEY_SHARES_CLIENT_TRUST_STORE_TYPE, "JKS");
        var clientTrustStorePw = properties.getProperty(KEY_SHARES_CLIENT_TRUST_STORE_PWD);
        var clientTrustStore = loadClientTrustKeyStore(
            clientTrustStoreFile,
            clientTrustStoreType,
            clientTrustStorePw
        );

        int readTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            KEY_SHARES_CLIENT_READ_TIMEOUT
        ).orElse(DEFAULT_READ_TIMEOUT_MS);

        int connectTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            KEY_SHARES_CLIENT_CONNECT_TIMEOUT
        ).orElse(DEFAULT_CONNECT_TIMEOUT_MS);

        Boolean clientServerDebug = getBoolean(properties, CLIENT_SERVER_DEBUG).orElse(false);

        return new KeySharesConfigurationProps(
            keySharesServersNum,
            keySharesServersUrls,
            keySharesServersMinNum,
            keySharesAlgorithm,
            clientTrustStore,
            readTimeout,
            connectTimeout,
            clientServerDebug
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
    public KeyStore getClientTrustStore() {
        return clientTrustStore;
    }

    @Override
    public int getReadTimeout() {
        return readTimeout;
    }

    @Override
    public int getConnectTimeout() {
        return connectTimeout;
    }

    @Override
    public boolean getClientServerDebug() {
        return clientServerDebug;
    }

}
