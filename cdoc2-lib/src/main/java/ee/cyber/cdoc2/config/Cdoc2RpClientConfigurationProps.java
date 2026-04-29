package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;

/**
 * CDOC2 Authentication Server Client configuration properties.
 *
 * @param hostUrl client host URL
 */
public record Cdoc2RpClientConfigurationProps(
    String hostUrl,
    String certificateLevel,
    String trustStore,
    String trustStorePassword
) implements Cdoc2RpClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2RpClientConfigurationProps.class);

    public static Cdoc2RpClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, RP_SERVER_CLIENT_HOST_URL);
        String certificateLevel = getRequiredProperty(properties, RP_SERVER_CLIENT_CERT_LEVEL);
        String trustStore = getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE);
        String trustStorePassword = getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE_PWD);

        return new Cdoc2RpClientConfigurationProps(
            hostUrl, certificateLevel, trustStore, trustStorePassword
        );
    }

    @Override
    public String getHostUrl() {
        return hostUrl;
    }

    @Override
    public String getCertificateLevel() {
        return certificateLevel;
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
