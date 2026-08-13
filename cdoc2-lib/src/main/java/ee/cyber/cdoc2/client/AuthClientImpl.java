package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.client.model.AuthProcessStatusResponse;
import ee.cyber.cdoc2.client.model.WellKnownResponse;
import ee.cyber.cdoc2.config.Cdoc2AuthClientConfiguration;

public final class AuthClientImpl implements AuthClient {
    private static final TimeUnit STATUS_POLL_SLEEP_TIMEUNIT = TimeUnit.MILLISECONDS;
    private static final String AUTH_PROCESS_STATUS_STARTED = "STARTED";

    private static final Logger log = LoggerFactory.getLogger(AuthClientImpl.class);
    private final Cdoc2AuthApiClient cdoc2AuthApiClient;
    private final String serverUrl;
    private final int pollingIntervalMs;
    private final int pollingMaxCount;

    private AuthClientImpl(
        Cdoc2AuthApiClient cdoc2AuthApiClient,
        Cdoc2AuthClientConfiguration config
    ) {
        this.cdoc2AuthApiClient = cdoc2AuthApiClient;
        this.serverUrl = config.getHostUrl();
        this.pollingIntervalMs = config.getPollingIntervalMs();
        this.pollingMaxCount = config.getPollingMaxCount();
    }

    public static AuthClient create(Cdoc2AuthClientConfiguration config)
        throws GeneralSecurityException {

        AuthClientBuilder builder = (AuthClientBuilder) Cdoc2AuthApiClient.builder()
            .withBaseUrl(config.getHostUrl())
            .withTrustKeyStore(config.getTrustStore())
            .withReadTimeoutMs(config.getReadTimeout())
            .withConnectTimeoutMs(config.getConnectTimeout())
            .withDebuggingEnabled(config.getClientServerDebug());

        return new AuthClientImpl(builder.build(), config);
    }

    @Override
    public Cdoc2AuthApiClient.AuthProcessData startAuth(@Nonnull AuthIdentity authIdentity)
        throws ExtApiException {

        log.debug("Starting authentication process for identity: {}", authIdentity);

        try {
            Cdoc2AuthApiClient.AuthProcessData response = cdoc2AuthApiClient.startAuth(authIdentity);

            log.info("Authentication process started, UUID: {}, VC: {}",
                response.uuid(),
                response.verificationCode()
            );
            return response;

        } catch (ApiException ex) {
            throw wrapApiException("Failed to start authentication process", ex);
        } catch (Exception ex) {
            throw wrapNetworkException(ex);
        }
    }

    @Override
    public AuthProcessStatusResponse pollForCompleteAuthProcessStatus(@Nonnull UUID authProcessUuid)
        throws ExtApiException {

        log.debug("Polling auth process status for UUID: {}", authProcessUuid);

        AuthProcessStatusResponse status = null;
        int pollCount = 0;
        try {
            while (status == null || AUTH_PROCESS_STATUS_STARTED.equals(status.getStatus())) {
                if (pollCount == this.pollingMaxCount) {
                    String message = "Max poll count reached when polling for complete auth "
                        + "process status. pollCount: "
                        + pollCount
                        + " status: "
                        + status;
                    log.error(message);

                    throw new ExtApiException(message);
                }

                status = cdoc2AuthApiClient.getAuthProcessStatus(authProcessUuid);

                if (status != null && !AUTH_PROCESS_STATUS_STARTED.equals(status.getStatus())) {
                    break;
                }
                log.debug("Incomplete auth process {} status: {}", authProcessUuid, status);
                log.debug("Sleeping for {} {}", this.pollingIntervalMs,
                    STATUS_POLL_SLEEP_TIMEUNIT);
                STATUS_POLL_SLEEP_TIMEUNIT.sleep(
                    this.pollingIntervalMs
                );
                pollCount++;
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

    @Override
    public WellKnownResponse getWellKnown() throws ExtApiException {
        log.debug("Fetching well-known JWKS");

        try {
            WellKnownResponse response = cdoc2AuthApiClient.getWellKnown();
            log.debug("Well-known JWKS retrieved successfully");
            return response;

        } catch (ApiException ex) {
            throw wrapApiException("Failed to retrieve well-known JWKS", ex);
        } catch (Exception ex) {
            throw wrapNetworkException(ex);
        }
    }

    private static ExtApiException wrapApiException(String context, ApiException ex) {
        String detail = switch (ex.getCode()) {
            case 400 -> "Bad request — check the parameters";
            case 401 -> "Unauthorized — missing or invalid auth ticket";
            case 403 -> "Forbidden — authentication failed";
            case 404 -> "Not found — record missing or recipient ID mismatch";
            default -> "Unexpected server response";
        };
        log.error("{}: {} (HTTP {}) — {}", context, detail, ex.getCode(), ex.getMessage());
        return new ExtApiException(
            context + ": " + detail + " (HTTP " + ex.getCode() + ") — " + ex.getMessage(), ex
        );
    }

    private ExtApiException wrapNetworkException(Exception ex) {
        log.error("{} {}: {}", "Failed to connect to authentication server",
            this.serverUrl,
            ex.getMessage(),
            ex
        );
        String detail = (ex.getCause() instanceof IOException)
            ? ex.getCause().getMessage()
            : ex.getMessage();
        return new ExtApiException(
            "Failed to connect to authentication server" + " " + this.serverUrl + ": " + detail,
            ex
        );
    }
}
