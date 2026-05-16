package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

public interface Cdoc2RpClientConfiguration {

    static Cdoc2RpClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        return Cdoc2RpClientConfigurationProps.load(properties);
    }

    String getHostUrl();
    String getCertificateLevel();
    String getTrustStore();
    String getTrustStorePassword();
    String getAuthenticationTrustStore();
    String getAuthenticationTrustStorePassword();
    boolean getClientServerDebug();
}
