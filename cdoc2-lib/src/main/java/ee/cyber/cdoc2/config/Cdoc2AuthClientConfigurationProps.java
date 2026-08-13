package ee.cyber.cdoc2.config;

import java.security.KeyStore;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ApiClientUtil;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getBoolean;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;

/**
 * CDOC2 Authentication Server Client configuration properties.
 *
 * @param hostUrl           client host URL
 * @param trustStore        client trust store
 * @param clientServerDebug turn on debug logs for client
 */
public record Cdoc2AuthClientConfigurationProps(
    String hostUrl,
    KeyStore trustStore,
    int readTimeout,
    int connectTimeout,
    int pollingIntervalMs,
    int pollingMaxCount,
    boolean clientServerDebug
) implements Cdoc2AuthClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2AuthClientConfigurationProps.class);
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 500;
    private static final int DEFAULT_POLLING_INTERVAL_MS = 1000;
    private static final int DEFAULT_POLLING_MAX_COUNT = 3;

    public static Cdoc2AuthClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, AUTH_SERVER_CLIENT_HOST_URL);
        KeyStore trustStore = ApiClientUtil.loadClientTrustKeyStore(
            getRequiredProperty(properties, AUTH_SERVER_CLIENT_TRUST_STORE),
            "JKS",
            getRequiredProperty(properties, AUTH_SERVER_CLIENT_TRUST_STORE_PWD)
        );

        int readTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            AUTH_SERVER_CLIENT_READ_TIMEOUT
        ).orElse(DEFAULT_READ_TIMEOUT_MS);

        int connectTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            AUTH_SERVER_CLIENT_CONNECT_TIMEOUT
        ).orElse(DEFAULT_CONNECT_TIMEOUT_MS);

        int pollingIntervalMs = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            AUTH_SERVER_CLIENT_POLLING_INTERVAL_MS
        ).orElse(DEFAULT_POLLING_INTERVAL_MS);

        int pollingMaxCount = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            AUTH_SERVER_CLIENT_POLLING_MAX_COUNT
        ).orElse(DEFAULT_POLLING_MAX_COUNT);

        Boolean clientServerDebug = getBoolean(properties, CLIENT_SERVER_DEBUG).orElse(false);

        return new Cdoc2AuthClientConfigurationProps(
            hostUrl, trustStore, readTimeout, connectTimeout,
            pollingIntervalMs, pollingMaxCount, clientServerDebug
        );
    }

    @Override
    public String getHostUrl() {
        return hostUrl;
    }

    @Override
    public KeyStore getTrustStore() {
        return trustStore;
    }

    @Override
    public int getReadTimeout() {
        return readTimeout;
    }

    @Override
    public int getConnectTimeout() {
        return connectTimeout;
    }

    @Override
    public int getPollingIntervalMs() {
        return pollingIntervalMs;
    }

    @Override
    public int getPollingMaxCount() {
        return pollingMaxCount;
    }

    @Override
    public boolean getClientServerDebug() {
        return clientServerDebug;
    }
}
