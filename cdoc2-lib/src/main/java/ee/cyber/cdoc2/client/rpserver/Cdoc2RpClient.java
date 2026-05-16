package ee.cyber.cdoc2.client.rpserver;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.ws.rs.client.ClientBuilder;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import javax.net.ssl.SSLContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.Cdoc2RpApi;
import ee.cyber.cdoc2.client.model.MidAuthenticateRequest;
import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidLanguage;
import ee.cyber.cdoc2.client.model.MidSessionStatusResponse;
import ee.cyber.cdoc2.client.model.SessionStatusResponse;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;
import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;
import ee.cyber.cdoc2.exceptions.CdocRpClientException;
import ee.cyber.cdoc2.util.ApiClientUtil;

public class Cdoc2RpClient {
    private static final Logger log = LoggerFactory.getLogger(Cdoc2RpClient.class);

    private final Cdoc2RpApi cdoc2RpApi;
    private final CertificateLevel certificateLevel;
    private final Cdoc2RpClientConfiguration cdoc2RpClientConfiguration;

    /**
     * Constructs a {@code Cdoc2AuthClient} from the supplied configuration.
     *
     * @param conf client configuration
     */
    public Cdoc2RpClient(@Nonnull Cdoc2RpClientConfiguration conf) {
        try {
            this.cdoc2RpApi = buildApi(conf);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | KeyStoreException
                 | KeyManagementException e) {
            throw new RuntimeException(e);
        }
        this.certificateLevel = CertificateLevel.valueOf(conf.getCertificateLevel());
        this.cdoc2RpClientConfiguration = conf;
    }

    public UUID sidAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull SidAuthenticateRequest request
    ) throws CdocRpClientException {
        try {
            return cdoc2RpApi.sidAuthenticateWithHttpInfo(
                xCdoc2SessionToken,
                xCdoc2SessionX5c,
                request
            ).getData().getSessionID();
        } catch (ApiException e) {
            throw wrapApiException("RP SID authenticate request error. ", e);
        }
    }

    public SessionStatusResponse sidSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws CdocRpClientException {
        try {
            return cdoc2RpApi.sidSession(sessionId, xCdoc2SessionToken, xCdoc2SessionX5c);
        } catch (ApiException e) {
            throw wrapApiException("RP SID session request error. ", e);
        }
    }

    public UUID midAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        String identityNumber,
        String phoneNumber,
        byte[] hash,
        String hashType,
        @Nullable InteractionParams interactionParams

    ) throws CdocRpClientException {
        try {
            MidAuthenticateRequest request = new MidAuthenticateRequest()
                .nationalIdentityNumber(identityNumber)
                .phoneNumber(phoneNumber)
                .hash(hash)
                .hashType(ee.cyber.cdoc2.client.model.MidHashType
                    .fromValue(hashType)
                )
                .displayText(getDisplayText(interactionParams))
                .language(getLanguage(interactionParams))
                .displayTextFormat(getEncoding(interactionParams));

            return cdoc2RpApi.midAuthenticateWithHttpInfo(
                xCdoc2SessionToken,
                xCdoc2SessionX5c,
                request
            ).getData().getSessionID();
        } catch (ApiException e) {
            throw wrapApiException("RP MID authenticate request error. ", e);
        }
    }

    public MidSessionStatusResponse midSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws CdocRpClientException {
        try {
            return cdoc2RpApi.midSession(sessionId, xCdoc2SessionToken, xCdoc2SessionX5c);
        } catch (ApiException e) {
            throw wrapApiException("RP MID session request error. ", e);
        }
    }

    public String getBaseUrl() {
        return cdoc2RpApi.getApiClient().getBasePath();
    }

    public String getCertificateLevel() {
        return certificateLevel.name();
    }

    private static Cdoc2RpApi buildApi(Cdoc2RpClientConfiguration conf)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        KeyStore trustStore = ApiClientUtil.loadClientTrustKeyStore(
            conf.getTrustStore(),
            "JKS",
            conf.getTrustStorePassword()
        );
        SSLContext sslContext = ApiClientUtil.createSslContext(trustStore, log);

        ee.cyber.cdoc2.client.api.ApiClient apiClient = new ee.cyber.cdoc2.client.api.ApiClient() {
            @Override
            protected void customizeClientBuilder(ClientBuilder clientBuilder) {
                if (sslContext != null) {
                    clientBuilder.sslContext(sslContext);
                }
            }
        };

        apiClient.setBasePath(conf.getHostUrl());

        log.info("Cdoc2AuthClient configured with base URL: {}", conf.getHostUrl());
        return new Cdoc2RpApi(apiClient);
    }

    /**
     * Get MID language from interactionParams if defined, otherwise get default value from configuration
     */
    protected MidLanguage getLanguage(@Nullable InteractionParams interactionParams) {
        MidLanguage lang = cdoc2RpClientConfiguration.getDefaultDisplayTextLanguage();
        if (interactionParams != null) {
            String iLang = interactionParams.getLanguage();
            if (iLang != null) {
                try {
                    lang = ee.cyber.cdoc2.client.model.MidLanguage.valueOf(iLang);
                } catch (IllegalArgumentException e) {
                    log.warn("Illegal MidLanguage value, using {}", lang, e);
                }
            }
        }
        return lang;
    }

    /**
     * Get MidDisplayTextFormat from interactionParams if defined, otherwise get default value from configuration
     */
    protected MidDisplayTextFormat getEncoding(@Nullable InteractionParams interactionParams) {
        MidDisplayTextFormat enc = cdoc2RpClientConfiguration.getDefaultDisplayTextFormat();
        if (interactionParams != null) {
            String iEnc = interactionParams.getEncoding();
            if (iEnc != null) {
                try {
                    enc = MidDisplayTextFormat.valueOf(iEnc);
                } catch (IllegalArgumentException e) {
                    log.warn("Illegal MidDisplayTextFormat value, using {}", enc, e);
                }
            }
        }

        return enc;
    }

    /**
     * Get displayText from interactionParams if defined, otherwise get default value from configuration
     */
    protected String getDisplayText(@Nullable InteractionParams interactionParams) {

        // Mobile-ID doesn't support interactionType and text length is limited to 100 bytes -
        // 50 chars for UCS2 and 100 chars for GSM7
        // https://github.com/SK-EID/MID?tab=readme-ov-file#323-request-parameters

        String textAndPIN = cdoc2RpClientConfiguration.getDefaultDisplayText();
        if (interactionParams != null) {
            textAndPIN = (getEncoding(interactionParams) == MidDisplayTextFormat.GSM_7)
                ? interactionParams.getDisplayText(100) // GSM7
                : interactionParams.getDisplayText(50); // UCS2
        }
        return textAndPIN;
    }

    private static CdocRpClientException wrapApiException(String context, ApiException ex) {
        String detail = switch (ex.getCode()) {
            case 400 -> "Bad request — check the parameters";
            case 401 -> "Unauthorized — session token validation failure";
            case 403 -> "Forbidden — authentication failed";
            case 404 -> "Not found — record missing or recipient ID mismatch";
            default -> "Unexpected server response";
        };
        log.error("{}: {} (HTTP {})", context, detail, ex.getCode());
        return new CdocRpClientException(context + ": " + detail + " (HTTP " + ex.getCode() + ")", ex);
    }

    enum CertificateLevel {
        ADVANCED,
        QUALIFIED
    }
}
