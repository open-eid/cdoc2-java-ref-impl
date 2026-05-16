package ee.cyber.cdoc2.client.rpserver;

import jakarta.annotation.Nonnull;
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
import ee.cyber.cdoc2.client.model.SessionStatusResponse;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;
import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.exceptions.CdocRpClientException;
import ee.cyber.cdoc2.util.ApiClientUtil;

public class Cdoc2RpClient {
    private static final Logger log = LoggerFactory.getLogger(Cdoc2RpClient.class);

    private final Cdoc2RpApi cdoc2RpApi;
    private final CertificateLevel certificateLevel;

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
    }

    public UUID authenticate(
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
            throw wrapApiException("RP authenticate request error. ", e);
        }
    }

    public SessionStatusResponse session(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws CdocRpClientException {
        try {
            return cdoc2RpApi.sidSession(sessionId, xCdoc2SessionToken, xCdoc2SessionX5c);
        } catch (ApiException e) {
            throw wrapApiException("RP session request error. ", e);
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
        apiClient.setDebugging(conf.getClientServerDebug());

        log.info("Cdoc2RpClient configured with base URL: {}", conf.getHostUrl());
        return new Cdoc2RpApi(apiClient);
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
