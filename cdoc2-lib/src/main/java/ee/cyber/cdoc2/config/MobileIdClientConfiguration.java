package ee.cyber.cdoc2.config;

import ee.sk.mid.MidDisplayTextFormat;
import ee.sk.mid.MidLanguage;

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

    int getLongPollingTimeoutSeconds();

    int getPollingSleepTimeoutSeconds();

    /** Default display text, can be overwritten with InteractionParams*/
    String getDefaultDisplayText();

    MidDisplayTextFormat getDefaultDisplayTextFormat();

    MidLanguage getDefaultDisplayTextLanguage();

}
