package ee.cyber.cdoc2.client;

import jakarta.annotation.Nonnull;

import java.util.UUID;

import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.client.model.AuthProcessStatusResponse;
import ee.cyber.cdoc2.client.model.WellKnownResponse;

public interface AuthClient {
    Cdoc2AuthApiClient.AuthProcessData startAuth(@Nonnull AuthIdentity authIdentity)
        throws ExtApiException;

    AuthProcessStatusResponse pollForCompleteAuthProcessStatus(@Nonnull UUID authProcessUuid) throws ExtApiException;

    WellKnownResponse getWellKnown() throws ExtApiException;
}
