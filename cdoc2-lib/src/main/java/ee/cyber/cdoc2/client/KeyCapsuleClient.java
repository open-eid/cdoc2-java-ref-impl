package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.client.model.Capsule;

import java.time.Duration;
import java.util.Optional;


/**
 * Generic capsule client
 */
public interface KeyCapsuleClient extends ServerClient {

    /**
     * When set, then client sends X-ExpiryTime header
     * @param duration Duration is converted into exact dateTime
     *                 when {@link #storeCapsule(Capsule)} is called
     */
    void setExpiryDuration(Duration duration);

    String storeCapsule(Capsule capsule) throws ExtApiException;

    Optional<Capsule> getCapsule(String id) throws ExtApiException;

}
