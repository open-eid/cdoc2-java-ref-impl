package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.util.UUID;

import ee.cyber.cdoc2.client.api.ApiResponse;
import ee.cyber.cdoc2.client.model.MidSessionStatusResponse;
import ee.cyber.cdoc2.client.model.SessionStatusResponse;
import ee.cyber.cdoc2.client.model.SidAuthenticateRequest;
import ee.cyber.cdoc2.crypto.jwt.InteractionParams;

public interface RpClient {
    UUID sidAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull SidAuthenticateRequest request
    ) throws ExtApiException;

    SessionStatusResponse sidSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws ExtApiException;

    UUID midAuthenticate(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        String identityNumber,
        String phoneNumber,
        byte[] hash,
        String hashType,
        InteractionParams interactionParams
    ) throws ExtApiException;

    ApiResponse<MidSessionStatusResponse> midSession(
        @Nonnull String xCdoc2SessionToken,
        @Nonnull String xCdoc2SessionX5c,
        @Nonnull UUID sessionId
    ) throws ExtApiException;

    String getBasePath();
    String getCertificateLevel();
}
