package ee.cyber.cdoc2.server.dto;

import ee.cyber.cdoc2.server.conf.LoadedKeyStore;

/**
 * Generated capsule
 *
 * @param keyStore      keystore with client certificate used by this user
 * @param request       the request payload for the server
 */
public record GeneratedCapsule(
    LoadedKeyStore keyStore,
    KeyCapsuleRequest request
) {
}
