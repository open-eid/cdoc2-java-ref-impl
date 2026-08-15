package ee.cyber.cdoc2.config;

import java.security.KeyStore;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidLanguage;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ApiClientUtil;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static ee.cyber.cdoc2.config.ConfigurationProperties.*;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getBoolean;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;

/**
 * CDOC2 Authentication Server Client configuration properties.
 *
 * @param hostUrl              client host URL
 * @param certificateLevel     Certificate level to use for SiD
 * @param trustStore           client trust store
 * @param readTimeout          read timeout
 * @param connectTimeout       connection timeout
 * @param midDisplayTextFormat MID displayText format
 * @param midLanguage          MID language
 * @param clientServerDebug    turn on debug logs for client
 */
public record RpClientConfigurationProps(
    String hostUrl,
    CertificateLevel certificateLevel,
    KeyStore trustStore,
    int readTimeout,
    int connectTimeout,
    MidDisplayTextFormat midDisplayTextFormat,
    MidLanguage midLanguage,
    boolean clientServerDebug
) implements RpClientConfiguration {
    private static final String DEFAULT_MID_DISPLAY_TEXT_FORMAT = "GSM_7";
    private static final String DEFAULT_MID_LANGUAGE = "ENG";
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 2000;

    public enum CertificateLevel {
        ADVANCED,
        QUALIFIED
    }

    private static final Logger log = LoggerFactory.getLogger(RpClientConfigurationProps.class);

    public static RpClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, RP_SERVER_CLIENT_HOST_URL);
        CertificateLevel certificateLevel =
            CertificateLevel.valueOf(
                getRequiredProperty(properties, RP_SERVER_CLIENT_CERT_LEVEL)
            );
        KeyStore trustStore = ApiClientUtil.loadClientTrustKeyStore(
            getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE),
            "JKS",
            getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE_PWD)
        );

        int readTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            RP_SERVER_CLIENT_READ_TIMEOUT
        ).orElse(DEFAULT_READ_TIMEOUT_MS);

        int connectTimeout = ConfigurationPropertyUtil.getInteger(
            log,
            properties,
            RP_SERVER_CLIENT_CONNECT_TIMEOUT
        ).orElse(DEFAULT_CONNECT_TIMEOUT_MS);

        MidDisplayTextFormat displayTextFormat = MidDisplayTextFormat.valueOf(
            properties.getProperty(RP_SERVER_MID_DISPLAY_TEXT_FORMAT, DEFAULT_MID_DISPLAY_TEXT_FORMAT)
        );
        MidLanguage language = MidLanguage.valueOf(
            properties.getProperty(RP_SERVER_MID_LANGUAGE, DEFAULT_MID_LANGUAGE)
        );
        Boolean clientServerDebug = getBoolean(properties, CLIENT_SERVER_DEBUG).orElse(false);

        return new RpClientConfigurationProps(
            hostUrl, certificateLevel, trustStore, readTimeout, connectTimeout,
            displayTextFormat, language, clientServerDebug
        );
    }

    @Override
    public String getHostUrl() {
        return hostUrl;
    }

    @Override
    public CertificateLevel getCertificateLevel() {
        return certificateLevel;
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
