package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidLanguage;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getBoolean;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;

/**
 * CDOC2 Authentication Server Client configuration properties.
 *
 * @param hostUrl            client host URL
 * @param certificateLevel   Certificate level to use for SiD
 * @param trustStore         client trust store
 * @param trustStorePassword client trust store password
 * @param midDisplayTextFormat  MID displayText format
 * @param midLanguage           MID language
 * @param clientServerDebug  turn on debug logs for client
 */
public record Cdoc2RpClientConfigurationProps(
    String hostUrl,
    String certificateLevel,
    String trustStore,
    String trustStorePassword,
    MidDisplayTextFormat midDisplayTextFormat,
    MidLanguage midLanguage,
    boolean clientServerDebug
) implements Cdoc2RpClientConfiguration {
    private static final String DEFAULT_MID_DISPLAY_TEXT_FORMAT = "GSM_7";
    private static final String DEFAULT_MID_LANGUAGE = "ENG";

    private static final Logger log = LoggerFactory.getLogger(Cdoc2RpClientConfigurationProps.class);

    public static Cdoc2RpClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, RP_SERVER_CLIENT_HOST_URL);
        String certificateLevel = getRequiredProperty(properties, RP_SERVER_CLIENT_CERT_LEVEL);
        String trustStore = getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE);
        String trustStorePassword = getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE_PWD);
        MidDisplayTextFormat displayTextFormat = MidDisplayTextFormat.valueOf(
            properties.getProperty(RP_SERVER_MID_DISPLAY_TEXT_FORMAT, DEFAULT_MID_DISPLAY_TEXT_FORMAT)
        );
        MidLanguage language = MidLanguage.valueOf(
            properties.getProperty(RP_SERVER_MID_LANGUAGE, DEFAULT_MID_LANGUAGE)
        );
        Boolean clientServerDebug = getBoolean(properties, CLIENT_SERVER_DEBUG).orElse(false);

        return new Cdoc2RpClientConfigurationProps(
            hostUrl, certificateLevel, trustStore, trustStorePassword,
            displayTextFormat, language, clientServerDebug
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

    @Override
    public MidDisplayTextFormat getMidDisplayTextFormat() {
        return midDisplayTextFormat;
    }

    @Override
    public MidLanguage getMidLanguage() {
        return midLanguage;
    }

    @Override
    public boolean getClientServerDebug() {
        return clientServerDebug;
    }
}
