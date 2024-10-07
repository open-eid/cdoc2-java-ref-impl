package ee.cyber.cdoc2.config;

import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


/**
 * Key shares configuration properties for key capsule client.
 *
 * @param keySharesServersNum number of key shares servers
 * @param keySharesServersUrls key shares servers URL-s
 * @param keySharesServersMinNum minimum quantity of key shares servers
 * @param keySharesAlgorithm key shares algorithm
 */
public record KeySharesConfiguration(
    int keySharesServersNum,
    List<String> keySharesServersUrls,
    int keySharesServersMinNum,
    String keySharesAlgorithm
) {
    private static final Logger log = LoggerFactory.getLogger(KeySharesConfiguration.class);

    public static KeySharesConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading Key Shares configuration for Key Capsule client.");

        var keySharesServersUrls = ConfigurationPropertyUtil.splitString(
            log,
            properties,
            KEY_SHARES_SERVERS_URLS
        );

        var keySharesServersNum = keySharesServersUrls.size();
        var keySharesServersMinNum = ConfigurationPropertyUtil.getRequiredInteger(
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

        return new KeySharesConfiguration(
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

}
