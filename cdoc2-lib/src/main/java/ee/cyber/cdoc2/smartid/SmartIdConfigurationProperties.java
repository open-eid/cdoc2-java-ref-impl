package ee.cyber.cdoc2.smartid;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


/**
 * Smart ID Client configuration properties.
 */
public record SmartIdConfigurationProperties(
    String hostUrl,
    String relyingPartyUuid,
    String relyingPartyName,
    String trustStorePassword
) {

    private static final String PROPERTIES_FILE_CLASSPATH = "smartid/smartid.properties";

    private static final String HOST_URL_PROP = "smartid.client.hostUrl";
    private static final String RELYING_PARTY_UUID_PROP = "smartid.client.relyingPartyUuid";
    private static final String RELYING_PARTY_NAME_PROP = "smartid.client.relyingPartyName";
    private static final String TRUSTSTORE_PASSWORD_PROP = "smartid.client.ssl.trust-store-password";

    public static SmartIdConfigurationProperties load() throws ConfigurationLoadingException {
        Properties properties = ConfigurationPropertyUtil.getLoadedProperties(PROPERTIES_FILE_CLASSPATH);
        String hostUrl = getRequiredProperty(properties, HOST_URL_PROP);
        String relyingPartyUuid = getRequiredProperty(properties, RELYING_PARTY_UUID_PROP);
        String relyingPartyName = getRequiredProperty(properties, RELYING_PARTY_NAME_PROP);
        String trustStorePassword = getRequiredProperty(properties, TRUSTSTORE_PASSWORD_PROP);

        return new SmartIdConfigurationProperties(
            hostUrl, relyingPartyUuid, relyingPartyName, trustStorePassword
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

}
