package ee.cyber.cdoc20.crypto;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidParameterSpecException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Curve values from {@link ee.cyber.cdoc20.fbs.recipients.EllipticCurve} defined as enum and mapped to
 * known elliptic curve names and oid's
 */
public enum EllipticCurve {
    UNKNOWN(ee.cyber.cdoc20.fbs.recipients.EllipticCurve.UNKNOWN, null, null),
    SECP384R1(ee.cyber.cdoc20.fbs.recipients.EllipticCurve.secp384r1, ECKeys.SECP_384_R_1, ECKeys.SECP_384_OID);

    private static final Logger log = LoggerFactory.getLogger(EllipticCurve.class);

    private final byte value;
    private final String name;
    private final String oid;

    EllipticCurve(byte value, String name, String oid) {
        this.value = value;
        this.name = name;
        this.oid = oid;
    }
    public byte getValue() {
        return value;
    }

    public String getName() {
        return name;
    }
    public String getOid() {
        return oid;
    }

    public boolean isValidKey(ECPublicKey key) throws GeneralSecurityException {
        switch (this) {
            case SECP384R1:
                return ECKeys.isValidSecP384R1(key);
            default:
                throw new IllegalStateException("isValidKey not implemented for " + this);
        }
    }

    public boolean isValidKeyPair(KeyPair keyPair) throws GeneralSecurityException {
        switch (this) {
            case SECP384R1:
                return ECKeys.isECSecp384r1(keyPair);
            default:
                throw new IllegalStateException("isValidKeyPair not implemented for " + this);
        }
    }

    /**
     * Key length in bytes. For secp384r1, its 384/8=48
     */
    public int getKeyLength() {
        switch (this) {
            case SECP384R1:
                return ECKeys.SECP_384_R_1_LEN_BYTES;
            default:
                throw new IllegalStateException("getKeyLength not implemented for " + this);
        }
    }

    public ECPublicKey decodeFromTls(ByteBuffer encoded) throws GeneralSecurityException {
        switch (this) {
            case SECP384R1:
                // calls also isValidSecP384R1
                return ECKeys.decodeSecP384R1EcPublicKeyFromTls(encoded);
            default:
                throw new IllegalStateException("decodeFromTls not implemented for " + this);
        }
    }

    public KeyPair generateEcKeyPair() throws GeneralSecurityException {
        return ECKeys.generateEcKeyPair(this.getName());
    }

    public static EllipticCurve forName(String name) throws NoSuchAlgorithmException {
        if (ECKeys.SECP_384_R_1.equalsIgnoreCase(name)) {
            return SECP384R1;
        }
        throw new NoSuchAlgorithmException("Unknown curve name " + name);
    }

    public static EllipticCurve forOid(String oid) throws NoSuchAlgorithmException {
        if (ECKeys.SECP_384_OID.equals(oid)) {
            return SECP384R1;
        }
        throw new NoSuchAlgorithmException("Unknown EC curve oid " + oid);
    }

    public static EllipticCurve forValue(byte value) throws NoSuchAlgorithmException {
        switch (value) {
            case ee.cyber.cdoc20.fbs.recipients.EllipticCurve.secp384r1:
                return SECP384R1;
            default:
                throw new NoSuchAlgorithmException("Unknown EC curve value " + value);
        }
    }

    /**
     * @param publicKey ECPublicKey
     * @return
     * @throws NoSuchAlgorithmException      if publicKey EC curve is not supported
     * @throws InvalidParameterSpecException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException           if publicKey is not ECPublicKey
     */
    public static EllipticCurve forPubKey(PublicKey publicKey) throws NoSuchAlgorithmException,
        InvalidParameterSpecException, NoSuchProviderException, InvalidKeyException {

        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            return forOid(ECKeys.getCurveOid(ecPublicKey));
        } else {
            throw new InvalidKeyException("Unsupported key algorithm " + publicKey.getAlgorithm());
        }
    }

    /**
     * Check if public key is supported by CDOC lib
     *
     * @param publicKey to check for encryption by CDOC
     * @return if publicKey is supported for encryption by CDOC
     */
    public static boolean isSupported(PublicKey publicKey) {
        try {
            EllipticCurve curve = forPubKey(publicKey);
            return curve.isValidKey((ECPublicKey) publicKey);
        } catch (GeneralSecurityException ge) {
            log.info("Unsupported public key {}", ge.toString());
            return false;
        }
    }

    /**
     * Supported curve names
     */
    public static String[] names() {
        return ee.cyber.cdoc20.fbs.recipients.EllipticCurve.names;
    }
}
