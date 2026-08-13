package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.security.GeneralSecurityException;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.model.MidAuthenticateRequest;
import ee.cyber.cdoc2.client.model.MidDisplayTextFormat;
import ee.cyber.cdoc2.client.model.MidHashType;
import ee.cyber.cdoc2.client.model.MidLanguage;
import ee.cyber.cdoc2.client.model.MidSessionStatusResponse;
import ee.cyber.cdoc2.client.model.SessionStatusResponse;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;
import ee.cyber.cdoc2.config.RpClientConfiguration;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;

import static ee.cyber.cdoc2.client.ClientUtil.wrapApiException;
import static ee.cyber.cdoc2.client.ClientUtil.wrapNetworkException;

public final class RpClientImpl implements RpClient {
    private static final Logger log = LoggerFactory.getLogger(RpClientImpl.class);
    private final Cdoc2RpApiClient cdoc2RpApiClient;
    private final String serverUrl;
    private final RpClientConfiguration rpClientConfiguration;

    private RpClientImpl(
        Cdoc2RpApiClient cdoc2RpApiClient,
        RpClientConfiguration config
    ) {
        this.cdoc2RpApiClient = cdoc2RpApiClient;
        this.serverUrl = config.getHostUrl();
        this.rpClientConfiguration = config;
    }

    public static RpClient create(RpClientConfiguration config) {

        RpClientBuilder builder = (RpClientBuilder) Cdoc2RpApiClient.builder()
            .withBaseUrl(config.getHostUrl())
            .withTrustKeyStore(config.getTrustStore())
            .withReadTimeoutMs(config.getReadTimeout())
            .withConnectTimeoutMs(config.getConnectTimeout())
            .withDebuggingEnabled(config.getClientServerDebug());

        try {
            return new RpClientImpl(builder.build(), config);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UUID sidAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull SidAuthenticateRequest request
    ) throws ExtApiException {
        try {
            return cdoc2RpApiClient.sidAuthenticate(
                xCdoc2SessionToken,
                xCdoc2SessionX5c,
                request
            );
        } catch (ApiException e) {
            throw wrapApiException("RP SID authenticate request error. ", e, log);
        } catch (Exception e) {
            throw wrapNetworkException(e, this.serverUrl, log);
        }
    }

    @Override
    public SessionStatusResponse sidSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws ExtApiException {
        try {
            return cdoc2RpApiClient.sidSession(xCdoc2SessionToken, xCdoc2SessionX5c, sessionId);
        } catch (ApiException e) {
            throw wrapApiException("RP SID session request error. ", e, log);
        } catch (Exception e) {
            throw wrapNetworkException(e, this.serverUrl, log);
        }
    }

    @Override
    public UUID midAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        String identityNumber,
        String phoneNumber,
        byte[] hash,
        String hashType,
        InteractionParams interactionParams
    ) throws ExtApiException {
        try {
            MidAuthenticateRequest request = new MidAuthenticateRequest()
                .nationalIdentityNumber(identityNumber)
                .phoneNumber(phoneNumber)
                .hash(hash)
                .hashType(MidHashType
                    .fromValue(hashType)
                )
                .displayText(getDisplayText(interactionParams))
                .language(getLanguage(interactionParams))
                .displayTextFormat(getEncoding(interactionParams));

            return cdoc2RpApiClient.midAuthenticate(
                xCdoc2SessionToken,
                xCdoc2SessionX5c,
                request
            );
        } catch (ApiException e) {
            throw wrapApiException("RP MID authenticate request error. ", e, log);
        } catch (Exception e) {
            throw wrapNetworkException(e, this.serverUrl, log);
        }
    }

    @Override
    public ApiResponse<MidSessionStatusResponse> midSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws ExtApiException {
        try {
            return cdoc2RpApiClient
                .midSession(xCdoc2SessionToken, xCdoc2SessionX5c, sessionId);
        } catch (ApiException e) {
            throw wrapApiException("RP MID session request error. ", e, log);
        } catch (Exception e) {
            throw wrapNetworkException(e, this.serverUrl, log);
        }
    }

    @Override
    public String getBasePath() {
        return cdoc2RpApiClient.getBasePath();
    }

    public String getCertificateLevel() {
        return rpClientConfiguration.getCertificateLevel().name();
    }

    /**
     * Get MID language from interactionParams if defined, otherwise get default value from configuration
     */
    private MidLanguage getLanguage(InteractionParams interactionParams) {
        if (interactionParams != null && interactionParams.getInteractionLanguage() != null) {
            return switch (interactionParams.getInteractionLanguage()) {
                case ET -> MidLanguage.EST;
                case EN -> MidLanguage.ENG;
                case RU -> MidLanguage.RUS;
                case LT -> MidLanguage.LIT;
            };
        }

        return rpClientConfiguration.getMidLanguage();
    }

    /**
     * Get MidDisplayTextFormat from interactionParams if defined, otherwise get default value from configuration
     */
    private MidDisplayTextFormat getEncoding(InteractionParams interactionParams) {
        MidDisplayTextFormat enc = rpClientConfiguration.getMidDisplayTextFormat();
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
     * Get displayText from interactionParams
     */
    private String getDisplayText(InteractionParams interactionParams) {

        // Mobile-ID doesn't support interactionType and text length is limited to 100 bytes -
        // 50 chars for UCS2 and 100 chars for GSM7
        // https://github.com/SK-EID/MID?tab=readme-ov-file#323-request-parameters

        return (getEncoding(interactionParams) == MidDisplayTextFormat.GSM_7)
            ? interactionParams.getDisplayText(100) // GSM7
            : interactionParams.getDisplayText(50);
    }
}
