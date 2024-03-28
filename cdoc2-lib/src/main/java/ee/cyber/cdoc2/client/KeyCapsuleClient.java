package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.client.model.Capsule;
import java.util.Optional;

/**
 * Generic capsule client
 */
public interface KeyCapsuleClient extends ServerClient {

    String storeCapsule(Capsule capsule) throws ExtApiException;

    Optional<Capsule> getCapsule(String id) throws ExtApiException;
}
