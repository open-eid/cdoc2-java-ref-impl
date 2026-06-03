package ee.cyber.cdoc2.client.authserver;

import jakarta.annotation.Nonnull;
import jakarta.ws.rs.client.ClientBuilder;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.Cdoc2AuthApi;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.client.model.AuthProcessStatusResponse;
import ee.cyber.cdoc2.client.model.WellKnownResponse;
import ee.cyber.cdoc2.config.Cdoc2AuthClientConfiguration;
import ee.cyber.cdoc2.exceptions.CdocAuthClientException;
import ee.cyber.cdoc2.util.ApiClientUtil;

public class Cdoc2AuthClient {
    private static final TimeUnit STATUS_POLL_SLEEP_TIMEUNIT = TimeUnit.SECONDS;
    private static final long STATUS_POLL_SLEEP_QUANTITY = 1L;
    private static final String AUTH_PROCESS_STATUS_STARTED = "STARTED";

    private static final Logger log = LoggerFactory.getLogger(Cdoc2AuthClient.class);

    /**
     * Matches the UUID at the end of a Location header like /auth/status/{authProcessUuid}
     */
    private static final Pattern AUTH_PROCESS_UUID_PATTERN =
        Pattern.compile("/auth/status/([^/]+)$");

    private final Cdoc2AuthApi authApi;

    /**
     * Constructs a {@code Cdoc2AuthClient} from the supplied configuration.
     *
     * @param conf client configuration
     */
    public Cdoc2AuthClient(@Nonnull Cdoc2AuthClientConfiguration conf) {
        try {
            KeyStore trustStore = ApiClientUtil.loadClientTrustKeyStore(
                conf.getTrustStore(),
                "JKS",
                conf.getTrustStorePassword()
            );
            this.authApi = buildApi(conf, trustStore);
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Starts an authentication process for the given identity.
     *
     * @param authIdentity the identity to authenticate
     * @return the {@code authProcessUuid} extracted from the {@code Location} response header
     * and the verification code from the requests body.
     * @throws CdocAuthClientException if the API call fails or the UUID cannot be extracted
     */
    public AuthProcessData startAuth(@Nonnull AuthIdentity authIdentity) throws CdocAuthClientException {
        log.debug("Starting authentication process for identity: {}", authIdentity);

        try {
            var response = authApi.startAuthWithHttpInfo(authIdentity);

            String location = extractLocation(response.getHeaders());
            UUID uuid = extractUuidFromLocation(location);

            String vc = response.getData().getVc();

            log.info("Authentication process started, UUID: {}, VC: {}", uuid, vc);
            return new AuthProcessData(uuid, vc);

        } catch (ApiException ex) {
            throw new CdocAuthClientException(
                "Failed to start authentication process (HTTP " + ex.getCode() + ")", ex);
        } catch (Exception ex) {
            throw wrapNetworkException(ex);
        }
    }

    /**
     * Get auth process status
     *
     * @param authProcessUuid the UUID returned by {@link #startAuth(AuthIdentity)}
     * @return the current {@link AuthProcessStatusResponse}
     * @throws CdocAuthClientException if the API call fails (e.g. 400, 401, 404)
     */
    public AuthProcessStatusResponse getAuthProcessStatus(@Nonnull UUID authProcessUuid)
        throws CdocAuthClientException {

        log.debug("Polling auth process status for UUID: {}", authProcessUuid);

        AuthProcessStatusResponse status = null;
        try {
            while (status == null || AUTH_PROCESS_STATUS_STARTED.equals(status.getStatus())) {
                status = authApi.getAuthProcessStatus(String.valueOf(authProcessUuid));

                if (status != null && !AUTH_PROCESS_STATUS_STARTED.equals(status.getStatus())) {
                    break;
                }
                log.debug("Incomplete auth process {} status: {}", authProcessUuid, status);
                log.debug("Sleeping for {} {}", STATUS_POLL_SLEEP_QUANTITY,
                    STATUS_POLL_SLEEP_TIMEUNIT);
                STATUS_POLL_SLEEP_TIMEUNIT.sleep(STATUS_POLL_SLEEP_QUANTITY);
            }
        } catch (ApiException ex) {
            throw wrapApiException(
                "Failed to retrieve auth process status for UUID: " + authProcessUuid, ex);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (Exception ex) {
            throw wrapNetworkException(ex);
        }

        return status;
    }

    /**
     * Retrieves the server's well-known JWKS signing-key information.
     *
     * @return {@link WellKnownResponse} containing the server's signing keys
     * @throws CdocAuthClientException if the API call fails
     */
    public WellKnownResponse getWellKnown() throws CdocAuthClientException {
        log.debug("Fetching well-known JWKS");

        try {
            WellKnownResponse response = authApi.getWellKnown();
            log.debug("Well-known JWKS retrieved successfully");
            return response;

        } catch (ApiException ex) {
            throw wrapApiException("Failed to retrieve well-known JWKS", ex);
        } catch (Exception ex) {
            throw wrapNetworkException(ex);
        }
    }

    private static Cdoc2AuthApi buildApi(Cdoc2AuthClientConfiguration conf, KeyStore trustStore)
        throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

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

        log.info("Cdoc2AuthClient configured with base URL: {}", conf.getHostUrl());
        return new Cdoc2AuthApi(apiClient);
    }

    private static String extractLocation(
        Map<String, List<String>> headers) throws CdocAuthClientException {

        for (var entry : headers.entrySet()) {
            if ("Location".equalsIgnoreCase(entry.getKey())) {
                java.util.List<String> values = entry.getValue();
                if (values != null && !values.isEmpty()) {
                    return values.get(0);
                }
            }
        }
        throw new CdocAuthClientException(
            "Response did not contain 'Location' header"
        );
    }

    private static UUID extractUuidFromLocation(String location) throws CdocAuthClientException {
        if (location == null || location.isBlank()) {
            throw new CdocAuthClientException(
                "Location header is blank; cannot extract authProcessUuid");
        }

        Matcher matcher = AUTH_PROCESS_UUID_PATTERN.matcher(location);
        if (!matcher.find()) {
            throw new CdocAuthClientException(
                "Location header does not match expected pattern "
                    + AUTH_PROCESS_UUID_PATTERN.pattern() + ": " + location);
        }

        String uuidString = matcher.group(1);

        try {
            return UUID.fromString(uuidString);
        } catch (IllegalArgumentException e) {
            throw new CdocAuthClientException(
                "Extracted authProcessUuid is not a valid UUID: " + uuidString, e);
        }
    }

    private CdocAuthClientException wrapNetworkException(Exception ex) {
        String baseUrl = authApi.getApiClient().getBasePath();
        log.error("{} {}: {}", "Failed to connect to authentication server", baseUrl, ex.getMessage(), ex);
        String detail = (ex.getCause() instanceof IOException)
            ? ex.getCause().getMessage()
            : ex.getMessage();
        return new CdocAuthClientException("Failed to connect to authentication server" + " " + baseUrl + ": " + detail, ex);
    }

    private static CdocAuthClientException wrapApiException(String context, ApiException ex) {
        String detail = switch (ex.getCode()) {
            case 400 -> "Bad request — check the parameters";
            case 401 -> "Unauthorized — missing or invalid auth ticket";
            case 403 -> "Forbidden — authentication failed";
            case 404 -> "Not found — record missing or recipient ID mismatch";
            default -> "Unexpected server response";
        };
        log.error("{}: {} (HTTP {})", context, detail, ex.getCode());
        return new CdocAuthClientException(context + ": " + detail + " (HTTP " + ex.getCode() + ")", ex);
    }
}
