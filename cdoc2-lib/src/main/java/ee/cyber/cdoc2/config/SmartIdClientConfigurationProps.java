package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


/**
 * Smart ID Client configuration properties.
 *
 * @param hostUrl client host URL
 * @param relyingPartyUuid relying party UUID
 * @param relyingPartyName relying party name
 * @param trustStore client trust store
 * @param trustStorePassword client trust store password
 */
public record SmartIdClientConfigurationProps(
    String hostUrl,
    String relyingPartyUuid,
    String relyingPartyName,
    String trustStore,
    String trustStorePassword
) implements SmartIdClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SmartIdClientConfigurationProps.class);

    public static SmartIdClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading Smart ID client configuration.");

        String hostUrl = getRequiredProperty(properties, SMART_ID_CLIENT_HOST_URL);
        String relyingPartyUuid = getRequiredProperty(properties, SMART_ID_CLIENT_RELYING_PARTY_UUID);
        String relyingPartyName = getRequiredProperty(properties, SMART_ID_CLIENT_RELYING_PARTY_NAME);
        String trustStore = getRequiredProperty(properties, SMART_ID_CLIENT_TRUST_STORE);
        String trustStorePassword = getRequiredProperty(properties, SMART_ID_CLIENT_TRUST_STORE_PWD);

        return new SmartIdClientConfigurationProps(
            hostUrl, relyingPartyUuid, relyingPartyName, trustStore, trustStorePassword
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
    public String getTrustStorePassword() {
        return trustStorePassword;
    }

}
