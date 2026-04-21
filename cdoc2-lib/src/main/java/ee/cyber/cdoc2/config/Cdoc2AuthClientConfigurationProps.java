package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.AUTH_SERVER_CLIENT_HOST_URL;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;

/**
 * CDOC2 Authentication Server Client configuration properties.
 *
 * @param hostUrl client host URL
 */
public record Cdoc2AuthClientConfigurationProps(
    String hostUrl
) implements Cdoc2AuthClientConfiguration {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2AuthClientConfigurationProps.class);

    public static Cdoc2AuthClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, AUTH_SERVER_CLIENT_HOST_URL);

        return new Cdoc2AuthClientConfigurationProps(
            hostUrl
        );
    }

    @Override
    public String getHostUrl() {
        return hostUrl;
    }
}
