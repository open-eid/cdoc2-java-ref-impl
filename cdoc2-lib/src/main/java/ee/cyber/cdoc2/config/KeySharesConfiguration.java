package ee.cyber.cdoc2.config;

import java.util.Properties;
import java.util.Set;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


public interface KeySharesConfiguration {

    static KeySharesConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        return KeySharesConfigurationProps.load(properties);
    }

    int getKeySharesServersNum();

    Set<String> getKeySharesServersUrls();

    int getKeySharesServersMinNum();

    String getKeySharesAlgorithm();

    String getClientTrustStore();

    String getClientTrustStoreType();

    String getClientTrustStorePw();

}
