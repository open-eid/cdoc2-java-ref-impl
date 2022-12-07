package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.client.ExtApiException;
import ee.cyber.cdoc20.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc20.container.CDocParseException;

import java.security.GeneralSecurityException;

/**
 * Classes that implement this interface, can derive KEK (key encryption key) using key material and key capsule client
 */
public interface KekDerivable {
    byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
            throws GeneralSecurityException, ExtApiException, CDocParseException;
}
