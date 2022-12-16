package ee.cyber.cdoc20.server.dto;

import ee.cyber.cdoc20.server.conf.LoadedKeyStore;
import java.security.KeyPair;

/**
 * Generated capsule
 *
 * @param keyStore      keystore with client certificate used by this user
 * @param senderKeyPair the generated ephemeral key pair
 * @param request       the request payload for the server
 */
public record GeneratedCapsule(
    LoadedKeyStore keyStore,
    KeyPair senderKeyPair,
    KeyCapsuleRequest request
) {
}
