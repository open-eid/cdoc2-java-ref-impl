package ee.cyber.cdoc2.smartid;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;


/**
 * Smart ID Client configuration properties.
 */
public class SmartIdConfigurationProperties {

    private static final String PROPERTIES_FILE_NAME = "smartid/smartid.properties";

    private static final String HOST_URL_PROP = "smartid.client.hostUrl";
    private static final String RELYING_PARTY_UUID_PROP = "smartid.client.relyingPartyUuid";
    private static final String RELYING_PARTY_NAME_PROP = "smartid.client.relyingPartyName";
    private static final String TRUSTSTORE_PASSWORD_PROP = "smartid.client.ssl.trust-store-password";

    private final String hostUrl;
    private final String relyingPartyUuid;
    private final String relyingPartyName;
    private final String trustStorePassword;

    public SmartIdConfigurationProperties() throws ConfigurationLoadingException {
        Properties properties = getProperties();
        this.hostUrl = properties.getProperty(HOST_URL_PROP);
        this.relyingPartyUuid = properties.getProperty(RELYING_PARTY_UUID_PROP);
        this.relyingPartyName = properties.getProperty(RELYING_PARTY_NAME_PROP);
        this.trustStorePassword = properties.getProperty(TRUSTSTORE_PASSWORD_PROP);
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

    private Properties getProperties() throws ConfigurationLoadingException {
        return loadProperties(PROPERTIES_FILE_NAME);
    }

}
