package ee.cyber.cdoc20.client;

import ee.cyber.cdoc20.client.model.Capsule;
import java.util.Optional;

/**
 * Generic capsule client
 */
public interface KeyCapsuleClient extends ServerClient {

    String storeCapsule(Capsule capsule) throws ExtApiException;

    Optional<Capsule> getCapsule(String id) throws ExtApiException;
}
