package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


public interface MobileIdClientConfiguration {

    static MobileIdClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        return MobileIdClientConfigurationProps.load(properties);
    }

    String getHostUrl();

    String getRelyingPartyUuid();

    String getRelyingPartyName();

    String getTrustStore();

    String getTrustStoreType();

    String getTrustStorePassword();

    int getLongPollingTimeout();

    int getPollingSleepTimeoutSeconds();
}
