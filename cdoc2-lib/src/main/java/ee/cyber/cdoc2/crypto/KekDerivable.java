package ee.cyber.cdoc2.crypto;

import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.CDocException;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;

import java.security.GeneralSecurityException;

/**
 * Classes that implement this interface, can derive KEK (key encryption key) using key material and key capsule client
 */
public interface KekDerivable {
    byte[] deriveKek(DecryptionKeyMaterial keyMaterial, KeyCapsuleClientFactory factory)
        throws GeneralSecurityException, CDocException;
}
