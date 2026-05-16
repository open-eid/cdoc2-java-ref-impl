package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidLanguage;
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
    String trustStorePassword,
    String sidSigningCertificateTrustStore,
    String sidSigningCertificateTrustStorePassword,
    String midSigningCertificateTrustStore,
    String midSigningCertificateTrustStorePassword,
    String displayText,
    MidDisplayTextFormat displayTextFormat,
    MidLanguage language
) implements Cdoc2RpClientConfiguration {
    private static final String DEFAULT_DISPLAY_TEXT = "Please confirm authentication";
    private static final String DEFAULT_DISPLAY_TEXT_FORMAT = "GSM_7";
    private static final String DEFAULT_DISPLAY_TEXT_LANG = "ENG";

    private static final Logger log = LoggerFactory.getLogger(Cdoc2RpClientConfigurationProps.class);

    public static Cdoc2RpClientConfiguration load(Properties properties)
        throws ConfigurationLoadingException {

        log.debug("Loading CDOC2 authentication server client configuration.");

        String hostUrl = getRequiredProperty(properties, RP_SERVER_CLIENT_HOST_URL);
        String certificateLevel = getRequiredProperty(properties, RP_SERVER_CLIENT_CERT_LEVEL);
        String trustStore = getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE);
        String trustStorePassword = getRequiredProperty(properties, RP_SERVER_CLIENT_TRUST_STORE_PWD);
        String sidSigningCertificateTrustStore =
            getRequiredProperty(properties, RP_SERVER_SID_SIGNING_CERTIFICATE_TRUST_STORE);
        String sidSigningCertificateTrustStorePassword =
            getRequiredProperty(properties, RP_SERVER_SID_SIGNING_CERTIFICATE_TRUST_STORE_PWD);
        String midSigningCertificateTrustStore =
            getRequiredProperty(properties, RP_SERVER_MID_SIGNING_CERTIFICATE_TRUST_STORE);
        String midSigningCertificateTrustStorePassword =
            getRequiredProperty(properties, RP_SERVER_MID_SIGNING_CERTIFICATE_TRUST_STORE_PWD);
        String displayText = properties.getProperty(
            RP_SERVER_MOBILE_ID_DISPLAY_TEXT, DEFAULT_DISPLAY_TEXT
        );
        MidDisplayTextFormat displayTextFormat = MidDisplayTextFormat.valueOf(
            properties.getProperty(RP_SERVER_MOBILE_ID_DISPLAY_TEXT_FORMAT, DEFAULT_DISPLAY_TEXT_FORMAT)
        );
        MidLanguage language = MidLanguage.valueOf(
            properties.getProperty(RP_SERVER_MOBILE_ID_DISPLAY_LANG, DEFAULT_DISPLAY_TEXT_LANG)
        );

        return new Cdoc2RpClientConfigurationProps(
            hostUrl, certificateLevel, trustStore, trustStorePassword,
            sidSigningCertificateTrustStore, sidSigningCertificateTrustStorePassword,
            midSigningCertificateTrustStore, midSigningCertificateTrustStorePassword,
            displayText, displayTextFormat, language
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
    public String getSidSigningCertificateTrustStore() {
        return sidSigningCertificateTrustStore;
    }

    @Override
    public String getSidSigningCertificateTrustStorePassword() {
        return sidSigningCertificateTrustStorePassword;
    }

    @Override
    public String getMidSigningCertificateTrustStore() {
        return midSigningCertificateTrustStore;
    }

    @Override
    public String getMidSigningCertificateTrustStorePassword() {
        return midSigningCertificateTrustStorePassword;
    }

    @Override
    public String getDefaultDisplayText() {
        return displayText;
    }

    @Override
    public MidDisplayTextFormat getDefaultDisplayTextFormat() {
        return displayTextFormat;
    }

    @Override
    public MidLanguage getDefaultDisplayTextLanguage() {
        return language;
    }
}
