package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getInteger;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


/**
 * Mobile ID Client configuration properties.
 *
 * @param hostUrl client host URL
 * @param relyingPartyUuid relying party UUID
 * @param relyingPartyName relying party name
 * @param trustStore client trust store
 * @param trustStoreType client trust store type
 * @param trustStorePassword client trust store password
 * @param longPollingTimeoutSeconds long polling timeout seconds
 * @param pollingSleepTimeoutSeconds polling sleep timeout seconds
 */
public record MobileIdClientConfigurationProps(
    String hostUrl,
    String relyingPartyUuid,
    String relyingPartyName,
    String trustStore,
    String trustStoreType,
    String trustStorePassword,
    int longPollingTimeoutSeconds,
    int pollingSleepTimeoutSeconds
) implements MobileIdClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(MobileIdClientConfigurationProps.class);

    private static final int DEFAULT_LONG_POLLING_TIMEOUT_SECONDS = 60;
    private static final int DEFAULT_POLLING_SLEEP_TIMEOUT_SECONDS = 3;

    public static MobileIdClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading Mobile ID client configuration.");

        String hostUrl = getRequiredProperty(properties, MOBILE_ID_CLIENT_HOST_URL);
        String relyingPartyUuid = getRequiredProperty(properties, MOBILE_ID_CLIENT_RELYING_PARTY_UUID);
        String relyingPartyName = getRequiredProperty(properties, MOBILE_ID_CLIENT_RELYING_PARTY_NAME);
        String trustStore = getRequiredProperty(properties, MOBILE_ID_CLIENT_TRUST_STORE);
        String trustStoreType = getRequiredProperty(properties, MOBILE_ID_CLIENT_TRUST_STORE_TYPE);
        String trustStorePassword = getRequiredProperty(properties, MOBILE_ID_CLIENT_TRUST_STORE_PWD);
        int longPollingTimeoutSeconds = getInteger(
            log,
            properties,
            MOBILE_ID_CLIENT_POLLING_TIMEOUT_SEC
        ).orElse(DEFAULT_LONG_POLLING_TIMEOUT_SECONDS);
        int pollingSleepTimeoutSeconds = getInteger(
            log,
            properties,
            MOBILE_ID_CLIENT_POLLING_SLEEP_TIMEOUT_SEC
        ).orElse(DEFAULT_POLLING_SLEEP_TIMEOUT_SECONDS);

        return new MobileIdClientConfigurationProps(
            hostUrl,
            relyingPartyUuid,
            relyingPartyName,
            trustStore,
            trustStoreType,
            trustStorePassword,
            longPollingTimeoutSeconds,
            pollingSleepTimeoutSeconds
        );
    }

    @Override
    public String getHostUrl() {
        return hostUrl;
    }

    @Override
    public String getRelyingPartyUuid() {
        return relyingPartyUuid;
    }

    @Override
    public String getRelyingPartyName() {
        return relyingPartyName;
    }

    @Override
    public String getTrustStore() {
        return trustStore;
    }

    @Override
    public String getTrustStoreType() {
        return trustStoreType;
    }

    @Override
    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    @Override
    public int getLongPollingTimeout() {
        return longPollingTimeoutSeconds;
    }

    @Override
    public int getPollingSleepTimeoutSeconds() {
        return pollingSleepTimeoutSeconds;
    }

}
