package ee.cyber.cdoc2.client;

import jakarta.annotation.Nullable;

import ee.cyber.cdoc2.client.model.Capsule;

import java.time.OffsetDateTime;
import java.util.Optional;


/**
 * Generic capsule client
 */
public interface KeyCapsuleClient extends ServerClient {

    String storeCapsule(Capsule capsule) throws ExtApiException;

    String storeCapsule(Capsule capsule, @Nullable OffsetDateTime xExpiryTime) throws ExtApiException;

    Optional<Capsule> getCapsule(String id) throws ExtApiException;

}
