package ee.cyber.cdoc2.config;

import java.security.KeyStore;
import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

public interface KeyCapsuleClientConfiguration {

    static KeyCapsuleClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {
        return KeyCapsuleClientConfigurationProps.load(properties);
    }

    String getClientServerId();

    KeyStore getClientKeyStore();

    KeyStore.ProtectionParameter getKeyStoreProtectionParameter();

    Integer getClientServerConnectTimeout();

    Integer getClientServerReadTimeout();

    Boolean getClientServerDebug();

    String getClientServerBaseUrlGet();

    String getClientServerBaseUrlPost();

    KeyStore getClientTrustStore();

}
