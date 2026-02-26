package ee.cyber.cdoc2.crypto;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.cyber.cdoc2.crypto.EllipticCurve.forPubKey;

/**
 * EC key generation, encoding and decoding. Supports secp256r1, secp384r1 and secp521r1.
 */
@SuppressWarnings("squid:S6706")
public final class ECKeys {

    private static final Logger log = LoggerFactory.getLogger(ECKeys.class);

    private ECKeys() { }

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    public static KeyPair generateEcKeyPair(EllipticCurve curve)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator =
            KeyPairGenerator.getInstance(KeyAlgorithm.Algorithm.EC.name());
        keyPairGenerator.initialize(new ECGenParameterSpec(curve.getName()));
        return keyPairGenerator.generateKeyPair();
    }

    // -------------------------------------------------------------------------
    // Encoding
    // -------------------------------------------------------------------------

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    public static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey) throws GeneralSecurityException {
        if (ECPoint.POINT_INFINITY.equals(ecPublicKey.getW())) {
            throw new IllegalArgumentException("Cannot encode infinity ECPoint");
        }
        EllipticCurve curve = EllipticCurve.forOid(getCurveOid(ecPublicKey));
        return encodeEcPubKeyForTls(curve, ecPublicKey);
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param curve the expected elliptic curve
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    @SuppressWarnings("checkstyle:LineLength")
    public static byte[] encodeEcPubKeyForTls(EllipticCurve curve, ECPublicKey ecPublicKey) {
        int keyLength = curve.getKeyLength();
        byte[] xBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineX(), keyLength);
        byte[] yBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineY(), keyLength);

        //CHECKSTYLE:OFF
        //EC pubKey in TLS 1.3 format
        //https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        //https://github.com/bcgit/bc-java/blob/526b5846653100fc521c1a68c02dbe9df3347a29/core/src/main/java/org/bouncycastle/math/ec/ECCurve.java#L410
        //CHECKSTYLE:ON
        byte[] tlsPubKey = new byte[1 + xBytes.length + yBytes.length];
        tlsPubKey[0] = 0x04; // uncompressed

        System.arraycopy(xBytes, 0, tlsPubKey, 1, xBytes.length);
        System.arraycopy(yBytes, 0, tlsPubKey, 1 + xBytes.length, yBytes.length);

        return tlsPubKey;
    }

    // -------------------------------------------------------------------------
    // Decoding
    // -------------------------------------------------------------------------

    public static ECPublicKey decodeEcPublicKeyFromTls(EllipticCurve curve, ByteBuffer encoded)
        throws GeneralSecurityException {
        return decodeEcPublicKeyFromTls(curve,
            Arrays.copyOfRange(encoded.array(), encoded.position(), encoded.limit()));
    }

    /**
     * Decode EcPublicKey from TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param curve the expected elliptic curve
     * @param encoded EC public key octets encoded as in TLS 1.3 format
     * @return decoded ECPublicKey
     * @throws GeneralSecurityException if key is invalid
     */
    public static ECPublicKey decodeEcPublicKeyFromTls(EllipticCurve curve, byte[] encoded)
        throws GeneralSecurityException {
        ECPublicKey ecPublicKey = decodeRawTlsBytes(encoded, curve);
        if (!isValidPublicKey(curve, ecPublicKey)) {
            throw new InvalidKeyException(
                "Not a valid " + curve.getName() + " EC public key: "
                    + HexFormat.of().formatHex(encoded));
        }
        return ecPublicKey;
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /**
     * Returns true if {@code ecPublicKey} is a valid public key on {@code curve}.
     * Performs null, infinity, curve-name, and point-on-curve checks.
     */
    public static boolean isValidPublicKey(EllipticCurve curve, ECPublicKey ecPublicKey)
        throws GeneralSecurityException {
        if (ecPublicKey == null) {
            log.debug("EC pub key is null");
            return false;
        }
        if (ECPoint.POINT_INFINITY.equals(ecPublicKey.getW())) {
            log.debug("EC pub key is infinity");
            return false;
        }
        if (getCurve(ecPublicKey) != curve) {
            log.debug("EC pub key curve OID {} is not {}", getCurveOid(ecPublicKey), curve.getName());
            return false;
        }

        // Delegate point-on-curve validation to BouncyCastle
        // https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
        org.bouncycastle.math.ec.ECPoint ecPoint = curve.getBcCurve().createPoint(
            ecPublicKey.getW().getAffineX(),
            ecPublicKey.getW().getAffineY());

        boolean onCurve = ecPoint.isValid();
        if (!onCurve) {
            log.debug("EC pub key is not on {} curve", curve.getName());
        }
        return onCurve;
    }

    /**
     * Returns true if the key pair's algorithm is EC and both keys are on the expected {@code curve}.
     */
    public static boolean isECKeyPairForCurve(EllipticCurve curve, KeyPair keyPair)
        throws GeneralSecurityException {
        if (!isEcKeyAlgorithm(keyPair.getPrivate().getAlgorithm(), keyPair.getPublic().getAlgorithm())) {
            return false;
        }
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        if (keyPair.getPrivate() instanceof ECKey ecPrivateKey) {
            return isValidPublicKey(curve, ecPublicKey) && getCurve(ecPrivateKey) == curve;
        } else {
            // Can't interrogate the curve for unextractable PKCS11 keys; trust the public key
            return isValidPublicKey(curve, ecPublicKey) && Crypto.isECPKCS11Key(keyPair.getPrivate());
        }
    }

    /**
     * Returns the {@link EllipticCurve} for the given key.
     */
    public static EllipticCurve getCurve(ECKey key) throws GeneralSecurityException {
        return EllipticCurve.forOid(getCurveOid(key));
    }

    /**
     * Returns the OID string of the curve used by the given key.
     * In practice SunEC and BC both return the OID form (e.g. {@code "1.3.132.0.34"})
     * rather than the human-readable name.
     */
    public static String getCurveOid(ECKey key)
        throws NoSuchAlgorithmException, InvalidParameterSpecException, NoSuchProviderException {
        AlgorithmParameters params =
            AlgorithmParameters.getInstance(KeyAlgorithm.Algorithm.EC.name(), "SunEC");
        params.init(key.getParams());
        return params.getParameterSpec(ECGenParameterSpec.class).getName();
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
            return isValidPublicKey(curve, (ECPublicKey) publicKey);
        } catch (GeneralSecurityException ge) {
            log.info("Unsupported public key {}", ge.toString());
            return false;
        }
    }

    /**
     * Derive EC public key from EC private key (and its curve)
     * @param ecPrivateKey EC private key
     * @return EC KeyPair where public key is derived from ecPrivateKey
     * @throws GeneralSecurityException
     */
    public static KeyPair deriveECPubKeyFromPrivKey(ECPrivateKey ecPrivateKey) throws GeneralSecurityException {
        KeyFactory keyFactory
            = KeyFactory.getInstance(KeyAlgorithm.Algorithm.EC.name(), new BouncyCastleProvider());

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(getCurveOid(ecPrivateKey));
        org.bouncycastle.math.ec.ECPoint q = spec.getG().multiply(ecPrivateKey.getS());
        PublicKey bcPublicKey = keyFactory.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(q, spec));

        ECPublicKey publicKey = ECKeys.decodeEcPublicKeyFromTls(
            EllipticCurve.forPubKey(bcPublicKey),
            encodeEcPubKeyForTls((ECPublicKey) bcPublicKey)
        );
        return new KeyPair(publicKey, ecPrivateKey);
    }


    // -------------------------------------------------------------------------
    // Key loading
    // -------------------------------------------------------------------------

    /**
     * Load OpenSSL generated EC private key
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * <code>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </code>
     * @param openSslPem OpenSSL generated EC private key in PEM
     * @return EC private key loaded from openSslPem
     */
    static ECPrivateKey loadECPrivateKey(String openSslPem) throws GeneralSecurityException, IOException {

        KeyPair keyPair = PemTools.loadKeyPair(openSslPem);
        var curve = EllipticCurve.forPubKey(keyPair.getPublic());
        if (!isECKeyPairForCurve(curve, keyPair)) {
            throw new IllegalArgumentException("Not EC key pair");
        }

        return (ECPrivateKey)keyPair.getPrivate();
    }

    /**
     * Load EC public keys from certificate files
     * @param certDerFiles x509 certificates
     * @return ECPublicKeys loaded from certificates
     * @throws CertificateException if cert file format is invalid
     * @throws IOException if error happens when reading certDerFiles
     */
    public static List<ECPublicKey> loadCertKeys(File[] certDerFiles) throws CertificateException, IOException {
        List<ECPublicKey> list = new LinkedList<>();
        if (certDerFiles != null) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            for (File f : certDerFiles) {
                InputStream in = Files.newInputStream(f.toPath());
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
                ECPublicKey ecPublicKey = (ECPublicKey) cert.getPublicKey();
                list.add(ecPublicKey);
            }
        }
        return list;
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static ECPublicKey decodeRawTlsBytes(byte[] encoded, EllipticCurve curve)
        throws GeneralSecurityException {
        int expectedLength = curve.getKeyLength();
        String encodedHex = HexFormat.of().formatHex(encoded);

        if (encoded.length != 2 * expectedLength + 1) {
            log.error("Invalid pubKey len {}, expected {}, encoded: {}", encoded.length, (2 * expectedLength + 1),
                encodedHex);
            throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
        }

        if (encoded[0] != 0x04) {
            log.error("Illegal EC pub key encoding. Encoded: {}", encodedHex);
            throw new IllegalArgumentException("Invalid encoding");
        }

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, expectedLength + 1));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, expectedLength + 1, encoded.length));

        AlgorithmParameters params = AlgorithmParameters.getInstance(KeyAlgorithm.Algorithm.EC.name());
        params.init(new ECGenParameterSpec(curve.getName()));
        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

        return (ECPublicKey) KeyFactory
            .getInstance(KeyAlgorithm.Algorithm.EC.name())
            .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecParameters));
    }

    private static byte[] toUnsignedByteArray(BigInteger bigInteger, int len) {
        Objects.requireNonNull(bigInteger, "Cannot convert null bigInteger to byte[]");
        //https://stackoverflow.com/questions/4407779/biginteger-to-byte
        byte[] array = bigInteger.toByteArray();
        if ((array[0] == 0) && (array.length == len + 1)) {
            return Arrays.copyOfRange(array, 1, array.length);
        } else if (array.length < len) {
            byte[] padded = new byte[len];
            System.arraycopy(array, 0, padded, len - array.length, array.length);
            return padded;
        } else {
            if ((array.length != len) && (log.isWarnEnabled())) {
                log.warn("Expected EC key to be {} bytes, but was {}. bigInteger: {}",
                    len, array.length, bigInteger.toString(16));
            }
            return array;
        }
    }

    private static boolean isEcKeyAlgorithm(String privateAlgorithm, String publicAlgorithm) {
        if (!KeyAlgorithm.isEcKeysAlgorithm(privateAlgorithm)) {
            log.debug("Not EC key pair. Private key algorithm is {} (expected EC)", privateAlgorithm);
            return false;
        }
        if (!KeyAlgorithm.isEcKeysAlgorithm(publicAlgorithm)) {
            log.debug("Not EC key pair. Public key algorithm is {} (expected EC)", publicAlgorithm);
            return false;
        }
        return true;
    }

}
