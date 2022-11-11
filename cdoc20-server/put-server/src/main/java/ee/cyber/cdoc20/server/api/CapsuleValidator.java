package ee.cyber.cdoc20.server.api;

import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

import ee.cyber.cdoc20.crypto.ECKeys;
import ee.cyber.cdoc20.server.model.Capsule;

/**
 * Utility class for validating capsules.
 */
@Slf4j
public final class CapsuleValidator {

    private CapsuleValidator() {
        // utility class
    }

    static boolean isValid(Capsule capsule) {
        switch (capsule.getCapsuleType()) {
            case ECC_SECP384R1:
                return validateEcSecp34r1Capsule(capsule);
            case RSA:
                return validateRSACapsule(capsule);
            default:
                throw new IllegalArgumentException("Unexpected capsule type: " + capsule.getCapsuleType());
        }
    }

    private static boolean validateEcSecp34r1Capsule(Capsule capsule) {
        try {
            var curve = ECKeys.EllipticCurve.secp384r1;
            int tlsEncodedKeyLen = 2 * curve.getKeyLength() + 1;

            if (capsule.getRecipientId() == null || capsule.getEphemeralKeyMaterial() == null) {
                log.error("Recipient id or ephemeral key was null");
                return false;
            }
            if (capsule.getRecipientId().length != tlsEncodedKeyLen
                    || capsule.getEphemeralKeyMaterial().length != tlsEncodedKeyLen) {
                log.error("Invalid secp384r1 curve key length");
                return false;
            }

            ECPublicKey recipientPubKey = curve.decodeFromTls(ByteBuffer.wrap(capsule.getRecipientId()));
            ECPublicKey senderPubKey = curve.decodeFromTls(ByteBuffer.wrap(capsule.getEphemeralKeyMaterial()));

            return curve.isValidKey(recipientPubKey) && curve.isValidKey(senderPubKey);
        } catch (GeneralSecurityException gse) {
            log.error("Invalid EC key", gse);
        }
        return false;
    }

    private static boolean validateRSACapsule(Capsule capsule) {
        try {
            var keySpec = new X509EncodedKeySpec(capsule.getRecipientId());
            KeyFactory.getInstance("RSA").generatePublic(keySpec);
            return true;
        } catch (GeneralSecurityException exc) {
            log.error("Failed to parse capsule recipient's RSA public key", exc);
            return false;
        }
    }
}
