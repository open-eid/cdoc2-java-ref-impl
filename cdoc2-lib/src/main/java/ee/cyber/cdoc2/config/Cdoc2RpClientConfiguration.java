package ee.cyber.cdoc2.config;

import java.security.KeyStore;
import java.util.Properties;

import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidLanguage;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

public interface Cdoc2RpClientConfiguration {

    static Cdoc2RpClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        return Cdoc2RpClientConfigurationProps.load(properties);
    }

    String getHostUrl();

    Cdoc2RpClientConfigurationProps.CertificateLevel getCertificateLevel();

    KeyStore getTrustStore();

    int getReadTimeout();

    int getConnectTimeout();

    MidDisplayTextFormat getMidDisplayTextFormat();

    MidLanguage getMidLanguage();

    boolean getClientServerDebug();
}
