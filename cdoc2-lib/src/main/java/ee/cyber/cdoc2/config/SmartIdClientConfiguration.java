package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


public interface SmartIdClientConfiguration {

    static SmartIdClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        return SmartIdClientConfigurationProps.load(properties);
    }

    String getHostUrl();

    String getRelyingPartyUuid();

    String getRelyingPartyName();

    String getTrustStore();

    String getTrustStorePassword();

}
