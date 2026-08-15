package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.util.UUID;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.api.Cdoc2RpApi;
import ee.cyber.cdoc2.client.model.MidAuthenticateRequest;
import ee.cyber.cdoc2.client.model.MidSessionStatusResponse;
import ee.cyber.cdoc2.client.model.SessionStatusResponse;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;

public class Cdoc2RpApiClient {
    private final Cdoc2RpApi rpApi;

    public Cdoc2RpApiClient(Cdoc2RpApi rpApi) {
        this.rpApi = rpApi;
    }

    public static RpClientBuilder builder() {
        return new RpClientBuilder();
    }

    /**
     * Performs SmartID RPv3 authenticate request
     *
     * @param xSessionToken       CDOC2 Session token (SDJWT)
     * @param xSessionCertificate PEM encoded X509 certificate (without newlines) that was used to
     *                            generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param request             SmartID RPv3 authenticate request structure
     * @return authentication session UUID
     * @throws ApiException on API errors
     */
    public UUID sidAuthenticate(
        @Nonnull String xSessionToken,
        @Nonnull String xSessionCertificate,
        @Nonnull SidAuthenticateRequest request
    ) throws ApiException {
        return rpApi.sidAuthenticateWithHttpInfo(
            xSessionToken,
            xSessionCertificate,
            request
        ).getData().getSessionID();
    }

    /**
     * Performs SmartID RPv3 session status request
     *
     * @param xSessionToken       CDOC2 Session token (SDJWT)
     * @param xSessionCertificate PEM encoded X509 certificate (without newlines) that was used to
     *                            generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param sessionId           session ID
     * @return SmartID RPv3 session status response structure
     * @throws ApiException on API errors
     */
    public SessionStatusResponse sidSession(
        @Nonnull String xSessionToken,
        @Nonnull String xSessionCertificate,
        @Nonnull UUID sessionId
    ) throws ApiException {
        return rpApi.sidSession(sessionId, xSessionToken, xSessionCertificate);
    }

    /**
     *
     * @param xSessionToken       CDOC2 Session token (SDJWT)
     * @param xSessionCertificate PEM encoded X509 certificate (without newlines) that was used to
     *                            generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param request             MobileID authenticate request structure
     * @return authentication session UUID
     * @throws ApiException on API errors
     */
    public UUID midAuthenticate(
        @Nonnull String xSessionToken,
        @Nonnull String xSessionCertificate,
        MidAuthenticateRequest request
    ) throws ApiException {
        return rpApi.midAuthenticateWithHttpInfo(
            xSessionToken,
            xSessionCertificate,
            request
        ).getData().getSessionID();
    }

    /**
     *
     * @param xSessionToken       CDOC2 Session token (SDJWT)
     * @param xSessionCertificate PEM encoded X509 certificate (without newlines) that was used to
     *                            generate the MID/SID signature in x-cdoc2-session-token payload.
     * @param sessionId           authentication session UUID
     * @return MobileID session status structure
     * @throws ApiException on API errors
     */
    public ApiResponse<MidSessionStatusResponse> midSession(
        @Nonnull String xSessionToken,
        @Nonnull String xSessionCertificate,
        @Nonnull UUID sessionId
    ) throws ApiException {
        return rpApi
            .midSessionWithHttpInfo(sessionId, xSessionToken, xSessionCertificate);
    }

    public String getBasePath() {
        return rpApi.getApiClient().getBasePath();
    }
}
