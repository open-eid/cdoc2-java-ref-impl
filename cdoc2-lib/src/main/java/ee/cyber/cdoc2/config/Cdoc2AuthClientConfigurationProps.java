package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getBoolean;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;

/**
 * CDOC2 Authentication Server Client configuration properties.
 *
 * @param hostUrl client host URL
 * @param trustStore client trust store
 * @param trustStorePassword client trust store password
 * @param clientServerDebug turn on debug logs for client
 */
public record Cdoc2AuthClientConfigurationProps(
    String hostUrl,
    String trustStore,
    String trustStorePassword,
    boolean clientServerDebug
) implements Cdoc2AuthClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2AuthClientConfigurationProps.class);

    public static Cdoc2AuthClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, AUTH_SERVER_CLIENT_HOST_URL);
        String trustStore = getRequiredProperty(properties, AUTH_SERVER_CLIENT_TRUST_STORE);
        String trustStorePassword = getRequiredProperty(properties,
            AUTH_SERVER_CLIENT_TRUST_STORE_PWD);
        Boolean clientServerDebug = getBoolean(properties, CLIENT_SERVER_DEBUG).orElse(false);

        return new Cdoc2AuthClientConfigurationProps(
            hostUrl, trustStore, trustStorePassword, clientServerDebug
        );
    }

    @Override
    public String getHostUrl() {
        return hostUrl;
    }

    @Override
    public String getTrustStore() {
        return trustStore;
    }

    @Override
    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    @Override
    public boolean getClientServerDebug() {
        return clientServerDebug;
    }
}
