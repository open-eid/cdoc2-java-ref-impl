package ee.cyber.cdoc2.smartid;

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
public record SmartIdClientConfiguration(
    String hostUrl,
    String relyingPartyUuid,
    String relyingPartyName,
    String trustStore,
    String trustStorePassword
) {
    private static final Logger log = LoggerFactory.getLogger(SmartIdClientConfiguration.class);

    public static SmartIdClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading Smart ID client configuration.");

        String hostUrl = getRequiredProperty(properties, SMART_ID_CLIENT_HOST_URL);
        String relyingPartyUuid = getRequiredProperty(properties, SMART_ID_CLIENT_RELYING_PARTY_UUID);
        String relyingPartyName = getRequiredProperty(properties, SMART_ID_CLIENT_RELYING_PARTY_NAME);
        String trustStore = getRequiredProperty(properties, SMART_ID_CLIENT_TRUST_STORE);
        String trustStorePassword = getRequiredProperty(properties, SMART_ID_CLIENT_TRUST_STORE_PWD);

        return new SmartIdClientConfiguration(
            hostUrl, relyingPartyUuid, relyingPartyName, trustStore, trustStorePassword
        );
    }

    public String getHostUrl() {
        return this.hostUrl;
    }

    public String getRelyingPartyUuid() {
        return this.relyingPartyUuid;
    }

    public String getRelyingPartyName() {
        return this.relyingPartyName;
    }

    public String getTrustStorePassword() {
        return this.trustStorePassword;
    }

    public String getTrustStore() {
        return this.trustStore;
    }

}
