package ee.cyber.cdoc2.crypto;

import ee.cyber.cdoc2.client.ExternalService;
import ee.cyber.cdoc2.crypto.keymaterial.DecryptionKeyMaterial;
import ee.cyber.cdoc2.exceptions.CDocException;

import java.security.GeneralSecurityException;


/**
 * Classes that implement this interface, can derive KEK (key encryption key) using key material and key capsule client
 */
public interface KekDerivable {

    default byte[] deriveKek(DecryptionKeyMaterial keyMaterial, ExternalService factory)
        throws GeneralSecurityException, CDocException {
        return null;
    }

}
