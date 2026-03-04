package ee.cyber.cdoc2.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Locale;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;


/**
 * Elliptic curve enums mapped to known elliptic curve names, OIDs, key lengths,
 * and their BouncyCastle curve instances for point validation.
 */
public enum EllipticCurve {

    UNKNOWN(
        null,
        null,
        0,
        null,
        ee.cyber.cdoc2.fbs.recipients.EllipticCurve.UNKNOWN
    ),
    SECP256R1(
        "secp256r1",
        "1.2.840.10045.3.1.7",
        256 / 8,
        new SecP256R1Curve(),
        ee.cyber.cdoc2.fbs.recipients.EllipticCurve.secp256r1
    ),
    SECP384R1(
        "secp384r1",
        "1.3.132.0.34",
        384 / 8, new SecP384R1Curve(),
        ee.cyber.cdoc2.fbs.recipients.EllipticCurve.secp384r1
    ),
    SECP521R1(
        "secp521r1",
            "1.3.132.0.35",
            521 / 8 + 1,
            new SecP521R1Curve(),
    ee.cyber.cdoc2.fbs.recipients.EllipticCurve.secp521r1
    );

    private final String name;
    private final String oid;
    private final int keyLengthBytes;
    private final ECCurve bcCurve;
    private final byte value;

    EllipticCurve(String name, String oid, int keyLengthBytes, ECCurve bcCurve, byte value) {
        this.name = name;
        this.oid = oid;
        this.keyLengthBytes = keyLengthBytes;
        this.bcCurve = bcCurve;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public String getOid() {
        return oid;
    }

    public byte getValue() {
        return value;
    }

    /**
     * Key length in bytes (e.g. 48 for secp384r1, 32 for secp256r1).
     */
    public int getKeyLength() {
        if (this == UNKNOWN) {
            throw new IllegalStateException("getKeyLength() not supported for UNKNOWN curve");
        }
        return keyLengthBytes;
    }

    /**
     * BouncyCastle ECCurve instance used for point-on-curve validation.
     */
    public ECCurve getBcCurve() {
        if (this == UNKNOWN) {
            throw new IllegalStateException("getBcCurve() not supported for UNKNOWN curve");
        }
        return bcCurve;
    }

    public static EllipticCurve forOid(String oid) throws NoSuchAlgorithmException {
        for (EllipticCurve curve : values()) {
            if (curve != UNKNOWN && curve.oid.equals(oid)) {
                return curve;
            }
        }

        throw new NoSuchAlgorithmException("Unknown EC curve OID: " + oid);
    }

    public static EllipticCurve forValue(byte value) throws NoSuchAlgorithmException {
        return switch (value) {
            case ee.cyber.cdoc2.fbs.recipients.EllipticCurve.secp256r1 -> SECP256R1;
            case ee.cyber.cdoc2.fbs.recipients.EllipticCurve.secp384r1 -> SECP384R1;
            case ee.cyber.cdoc2.fbs.recipients.EllipticCurve.secp521r1 -> SECP521R1;
            default -> throw new NoSuchAlgorithmException("Unknown EC curve value " + value);
        };
    }

    public static EllipticCurve forName(String name) throws NoSuchAlgorithmException {
        for (EllipticCurve curve : values()) {
            if (curve != UNKNOWN && curve.name.equals(name.toLowerCase(Locale.ROOT))) {
                return curve;
            }
        }
        throw new NoSuchAlgorithmException("Unknown EC curve name: " + name);
    }

    /**
     * @param publicKey ECPublicKey
     * @return EllipticCurve
     * @throws NoSuchAlgorithmException      if publicKey EC curve is not supported
     * @throws InvalidParameterSpecException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException           if publicKey is not ECPublicKey
     */
    public static EllipticCurve forPubKey(PublicKey publicKey) throws NoSuchAlgorithmException,
        InvalidParameterSpecException, NoSuchProviderException, InvalidKeyException {

        if (publicKey instanceof ECPublicKey ecPublicKey) {
            return forOid(ECKeys.getCurveOid(ecPublicKey));
        } else {
            throw new InvalidKeyException("Unsupported key algorithm " + publicKey.getAlgorithm());
        }
    }

}
