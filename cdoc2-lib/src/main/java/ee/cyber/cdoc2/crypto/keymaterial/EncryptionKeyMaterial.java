package ee.cyber.cdoc2.crypto.keymaterial;

import ee.cyber.cdoc2.crypto.EncryptionKeyOrigin;
import ee.cyber.cdoc2.crypto.KeyLabelParams;
import ee.cyber.cdoc2.crypto.KeyLabelTools;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.EncryptionKeyMaterialCollectionBuilder;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.PasswordEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.PublicKeyEncryptionKeyMaterial;
import ee.cyber.cdoc2.crypto.keymaterial.encrypt.SecretEncryptionKeyMaterial;

import javax.crypto.SecretKey;

import java.security.PublicKey;
import java.util.Objects;

import static ee.cyber.cdoc2.CDocConfiguration.isKeyLabelMachineReadableFormatEnabled;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createPublicKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSecretKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.createSymmetricKeyLabelParams;
import static ee.cyber.cdoc2.crypto.KeyLabelTools.formatKeyLabel;


/**
 * Represents key material required for encryption.
 */
public interface EncryptionKeyMaterial {

    /**
     * @return identifier for the encryption key
     */
    String getLabel();

    /**
     * Identifies the origin of key derivation. This data is used to find the correct
     * encryption algorithm.
     * @return EncryptionKeyOrigin encryption key origin
     */
    EncryptionKeyOrigin getKeyOrigin();

    /**
     * For backward compatibility. This method doesn't support correct keylabel generation as there
     * is no info, where pubKey is coming from (pubkey, cert, LDAP)
     * Use {@link #fromPublicKey(PublicKey, KeyLabelParams)} instead.
     * @deprecated ecryption key
     * @param pubKey public key
     * @param keyLabel key label
     * @return EncryptionKeyMaterial
     */
    @Deprecated(forRemoval = true)
    static EncryptionKeyMaterial fromPublicKey(
        PublicKey pubKey,
        String keyLabel
    ) {
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createPublicKeyLabelParams(keyLabel, null);
            return fromPublicKey(pubKey, keyLabelParams);
        } else {
            return new PublicKeyEncryptionKeyMaterial(pubKey, keyLabel);
        }
    }

    /**
     * Create EncryptionKeyMaterial from publicKey and keyLabel. To decrypt CDOC, recipient must have
     * the private key part of the public key. RSA and EC public keys are supported by CDOC.
     * @param pubKey public key
     * @param keyLabelParams public key information, see
     *            https://open-eid.github.io/CDOC2/1.1/02_protocol_and_cryptography_spec/appendix_d_keylabel/
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromPublicKey(
        PublicKey pubKey,
        KeyLabelParams keyLabelParams
    ) {
        Objects.requireNonNull(pubKey);
        EncryptionKeyOrigin origin = EncryptionKeyOrigin.PUBLIC_KEY;
        if (!keyLabelParams.isFromOrigin(origin)) {
            throw new IllegalArgumentException("KeyLabelParams must be of type " + origin);
        }

        KeyLabelParams labelParams = (keyLabelParams == null)
            ? createPublicKeyLabelParams(null, null)
            : keyLabelParams;

        return new PublicKeyEncryptionKeyMaterial(pubKey, formatKeyLabel(labelParams));
    }

    static EncryptionKeyMaterial fromPassword(char[] passwordChars, String keyLabel) {
        Objects.requireNonNull(passwordChars);
        Objects.requireNonNull(keyLabel);
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createSymmetricKeyLabelParams(
                EncryptionKeyOrigin.PASSWORD, keyLabel
            );
            return new PasswordEncryptionKeyMaterial(passwordChars, formatKeyLabel(keyLabelParams));
        } else {
            return new PasswordEncryptionKeyMaterial(passwordChars, keyLabel);
        }
    }

    /**
     * Create SecretEncryptionKeyMaterial from pre-shared key and keyLabel. KeyLabel can be in plain
     * text or as data params.
     * To decrypt CDOC, recipient must have same preSharedKey and salt that are identified by
     * the same keyLabel.
     * @param preSharedKey pre-shared key from secret key
     * @param keyLabel key label
     * @return EncryptionKeyMaterial object
     */
    static EncryptionKeyMaterial fromSecret(
        SecretKey preSharedKey,
        String keyLabel
    ) {
        if (isKeyLabelMachineReadableFormatEnabled()) {
            KeyLabelParams keyLabelParams = createSecretKeyLabelParams(keyLabel);
            return new SecretEncryptionKeyMaterial(preSharedKey, formatKeyLabel(keyLabelParams));
        } else {
            return new SecretEncryptionKeyMaterial(preSharedKey, keyLabel);
        }
    }


    static EncryptionKeyMaterial fromSecret(
        SecretKey preSharedKey,
        KeyLabelParams keyLabelParams
    ) {
        Objects.requireNonNull(preSharedKey);
        Objects.requireNonNull(keyLabelParams);
        KeyLabelTools.KeyLabelDataFields label = KeyLabelTools.KeyLabelDataFields.LABEL;
        if (!keyLabelParams.isFromOrigin(EncryptionKeyOrigin.SECRET)
            || !keyLabelParams.hasParam(label)) {
            throw new IllegalArgumentException("KeyLabelParams must be of type "
                + KeyLabelTools.KeyLabelType.SECRET + " and have a parameter " + label);
        }

        return new SecretEncryptionKeyMaterial(preSharedKey, formatKeyLabel(keyLabelParams));
    }

    static EncryptionKeyMaterialCollectionBuilder collectionBuilder() {
        return new EncryptionKeyMaterialCollectionBuilder();
    }

}
