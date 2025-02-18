package ee.cyber.cdoc2.config;

import java.security.KeyStore;
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

    KeyStore getClientTrustStore();

}
