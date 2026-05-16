package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

public interface Cdoc2AuthClientConfiguration {

    static Cdoc2AuthClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        return Cdoc2AuthClientConfigurationProps.load(properties);
    }

    String getHostUrl();
    String getTrustStore();
    String getTrustStorePassword();
    boolean getClientServerDebug();
}
