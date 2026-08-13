package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.security.GeneralSecurityException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.client.model.AuthProcessStatusResponse;
import ee.cyber.cdoc2.client.model.WellKnownResponse;
import ee.cyber.cdoc2.config.AuthClientConfiguration;

import static ee.cyber.cdoc2.client.ClientUtil.wrapApiException;
import static ee.cyber.cdoc2.client.ClientUtil.wrapNetworkException;

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
        AuthClientConfiguration config
    ) {
        this.cdoc2AuthApiClient = cdoc2AuthApiClient;
        this.serverUrl = config.getHostUrl();
        this.pollingIntervalMs = config.getPollingIntervalMs();
        this.pollingMaxCount = config.getPollingMaxCount();
    }

    public static AuthClient create(AuthClientConfiguration config)
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
            throw wrapApiException("Failed to start authentication process", ex, log);
        } catch (Exception ex) {
            throw wrapNetworkException(ex, this.serverUrl, log);
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
                checkForPollMaxCount(pollCount, status);

                status = getAuthProcessStatus(authProcessUuid);

                if (status != null && !AUTH_PROCESS_STATUS_STARTED.equals(status.getStatus())) {
                    break;
                }
                log.debug("Incomplete auth process {} status: {}", authProcessUuid, status);

                pollSleep();

                pollCount++;
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        return status;
    }

    private AuthProcessStatusResponse getAuthProcessStatus(@Nonnull UUID authProcessUuid)
        throws ExtApiException {
        try {
            return cdoc2AuthApiClient.getAuthProcessStatus(authProcessUuid);
        } catch (ApiException ex) {
            throw wrapApiException(
                "Failed to retrieve auth process status for UUID: " + authProcessUuid, ex, log
            );
        } catch (Exception ex) {
            throw wrapNetworkException(ex, this.serverUrl, log);
        }
    }

    private void checkForPollMaxCount(int pollCount, AuthProcessStatusResponse status) throws ExtApiException {
        if (pollCount == this.pollingMaxCount) {
            String message = "Max poll count reached when polling for complete auth "
                + "process status. pollCount: "
                + pollCount
                + " status: "
                + status;
            log.error(message);

            throw new ExtApiException(message);
        }
    }

    private void pollSleep() throws InterruptedException {
        log.debug("Sleeping for {} {}", this.pollingIntervalMs,
            STATUS_POLL_SLEEP_TIMEUNIT);
        STATUS_POLL_SLEEP_TIMEUNIT.sleep(
            this.pollingIntervalMs
        );
    }

    @Override
    public WellKnownResponse getWellKnown() throws ExtApiException {
        log.debug("Fetching well-known JWKS");

        try {
            WellKnownResponse response = cdoc2AuthApiClient.getWellKnown();
            log.debug("Well-known JWKS retrieved successfully");
            return response;

        } catch (ApiException ex) {
            throw wrapApiException("Failed to retrieve well-known JWKS", ex, log);
        } catch (Exception ex) {
            throw wrapNetworkException(ex, this.serverUrl, log);
        }
    }
}
