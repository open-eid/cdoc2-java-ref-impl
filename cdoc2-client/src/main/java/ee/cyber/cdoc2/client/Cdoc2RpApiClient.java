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
     *
     * @param xCdoc2SessionToken
     * @param xCdoc2SessionX5c
     * @param request
     * @return
     * @throws ApiException
     */
    public UUID sidAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull SidAuthenticateRequest request
    ) throws ApiException {
        return rpApi.sidAuthenticateWithHttpInfo(
            xCdoc2SessionToken,
            xCdoc2SessionX5c,
            request
        ).getData().getSessionID();
    }

    /**
     *
     * @param xCdoc2SessionToken
     * @param xCdoc2SessionX5c
     * @param sessionId
     * @return
     * @throws ApiException
     */
    public SessionStatusResponse sidSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws ApiException {
        return rpApi.sidSession(sessionId, xCdoc2SessionToken, xCdoc2SessionX5c);
    }

    /**
     *
     * @param xCdoc2SessionToken
     * @param xCdoc2SessionX5c
     * @param request
     * @return
     * @throws ApiException
     */
    public UUID midAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        MidAuthenticateRequest request
    ) throws ApiException {
        return rpApi.midAuthenticateWithHttpInfo(
            xCdoc2SessionToken,
            xCdoc2SessionX5c,
            request
        ).getData().getSessionID();
    }

    /**
     *
     * @param xCdoc2SessionToken
     * @param xCdoc2SessionX5c
     * @param sessionId
     * @return
     * @throws ApiException
     */
    public ApiResponse<MidSessionStatusResponse> midSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws ApiException {
        return rpApi
            .midSessionWithHttpInfo(sessionId, xCdoc2SessionToken, xCdoc2SessionX5c);
    }

    public String getBasePath() {
        return rpApi.getApiClient().getBasePath();
    }
}
