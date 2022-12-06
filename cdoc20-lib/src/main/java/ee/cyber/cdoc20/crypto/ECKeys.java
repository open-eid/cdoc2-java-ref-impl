package ee.cyber.cdoc20.crypto;

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
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EC keys loading, decoding and encoding. Currently, supports only secp384r1 EC keys.
 */
public final class ECKeys {
    public static final String EC_ALGORITHM_NAME = "EC";

    //https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html#GUID-091BF58C-82AB-4C9C-850F-1660824D5254
    public static final String SECP_384_R_1 = "secp384r1";
    public static final String SECP_384_OID = "1.3.132.0.34";

    /**
     * Key length for secp384r1 curve in bytes
     */
    public static final int SECP_384_R_1_LEN_BYTES = 384 / 8;

    // for validating that decoded ECPoints are valid for secp384r1 curve
    private static final ECCurve SECP_384_R_1_CURVE = new SecP384R1Curve();

    private static final Logger log = LoggerFactory.getLogger(ECKeys.class);

    private ECKeys() {
    }

    public static KeyPair generateEcKeyPair(String ecCurveName)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec(ecCurveName));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param curve EC curve that this ecPublicKey uses. Used to get curve key length.
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    public static byte[] encodeEcPubKeyForTls(EllipticCurve curve, ECPublicKey ecPublicKey) {
        int keyLength = curve.getKeyLength();
        return encodeEcPubKeyForTls(ecPublicKey, keyLength);
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    public static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey) throws GeneralSecurityException {
        if (ECPoint.POINT_INFINITY.equals(ecPublicKey.getW())) {
            throw new IllegalArgumentException("Cannot encode infinity ECPoint");
        }
        EllipticCurve curve = EllipticCurve.forOid(ECKeys.getCurveOid(ecPublicKey));
        int keyLength = curve.getKeyLength();
        return encodeEcPubKeyForTls(ecPublicKey, keyLength);
    }

    @SuppressWarnings("checkstyle:LineLength")
    private static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey, int keyLength) {
        byte[] xBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineX(), keyLength);
        byte[] yBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineY(), keyLength);

        //CHECKSTYLE:OFF
        //EC pubKey in TLS 1.3 format
        //https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        //https://github.com/bcgit/bc-java/blob/526b5846653100fc521c1a68c02dbe9df3347a29/core/src/main/java/org/bouncycastle/math/ec/ECCurve.java#L410
        //CHECKSTYLE:ON
        byte[] tlsPubKey = new byte[1 + xBytes.length + yBytes.length];
        tlsPubKey[0] = 0x04; //uncompressed

        System.arraycopy(xBytes, 0, tlsPubKey, 1, xBytes.length);
        System.arraycopy(yBytes, 0, tlsPubKey,  1 + xBytes.length, yBytes.length);

        return tlsPubKey;
    }

    static ECPublicKey decodeSecP384R1EcPublicKeyFromTls(ByteBuffer encoded) throws GeneralSecurityException {
        return decodeSecP384R1EcPublicKeyFromTls(
                Arrays.copyOfRange(encoded.array(), encoded.position(), encoded.limit()));
    }

    /**
     * Decode EcPublicKey from TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param encoded EC public key octets encoded as in TLS 1.3 format. Expects key to be part of secp384r1 curve
     * @return decoded ECPublicKey
     * @throws GeneralSecurityException
     */
    private static ECPublicKey decodeSecP384R1EcPublicKeyFromTls(byte[] encoded) throws GeneralSecurityException {

        String encodedHex = HexFormat.of().formatHex(encoded);
        final int expectedLength = SECP_384_R_1_LEN_BYTES;
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

        ECPoint pubPoint = new ECPoint(x, y);
        AlgorithmParameters params = AlgorithmParameters.getInstance(EC_ALGORITHM_NAME);
        params.init(new ECGenParameterSpec(SECP_384_R_1));

        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubECSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance(EC_ALGORITHM_NAME).generatePublic(pubECSpec);
        if (!isValidSecP384R1(ecPublicKey)) {
            throw new InvalidKeyException("Not valid secp384r1 EC public key " + encodedHex);
        }
        return ecPublicKey;
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
            if (array.length != len) {
                log.warn("Expected EC key to be {} bytes, but was {}. bigInteger: {}",
                        len, array.length, bigInteger.toString(16));
            }
            return array;
        }
    }

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
    public static ECPrivateKey loadECPrivateKey(String openSslPem) throws GeneralSecurityException, IOException {

        KeyPair keyPair = PemTools.loadKeyPair(openSslPem);
        if (!isECSecp384r1(keyPair)) {
            throw new IllegalArgumentException("Not EC key pair");
        }

        return (ECPrivateKey)keyPair.getPrivate();
    }

    public static String getCurveOid(ECKey key)
            throws NoSuchAlgorithmException, InvalidParameterSpecException, NoSuchProviderException {

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "SunEC");
        params.init(key.getParams());

        // JavaDoc NamedParameterSpec::getName() : Returns the standard name that determines the algorithm parameters.
        // and https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#parameterspec-names
        // lists "secp384r1" as standard name.
        // But in practice SunEC and BC both return "1.3.132.0.34"
        return params.getParameterSpec(ECGenParameterSpec.class).getName();
    }

    public static boolean isEcSecp384r1Curve(ECKey key) throws GeneralSecurityException {
        // https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html
        // Table 4-28 Recommended Curves Provided by the SunEC Provider
        final String[] secp384r1Names = {SECP_384_OID, SECP_384_R_1, "NIST P-384"};
        String oid = getCurveOid(key);
        return Arrays.asList(secp384r1Names).contains(oid);
    }

    public static boolean isECSecp384r1(KeyPair keyPair) throws GeneralSecurityException {
        if (!EC_ALGORITHM_NAME.equals(keyPair.getPrivate().getAlgorithm())) {
            log.debug("Not EC key pair. Algorithm is {} (expected EC)", keyPair.getPrivate().getAlgorithm());
            return false;
        }

        if (!EC_ALGORITHM_NAME.equals(keyPair.getPublic().getAlgorithm())) {
            log.debug("Not EC key pair. Algorithm is {} (expected EC)", keyPair.getPublic().getAlgorithm());
            return false;
        }

        ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
        if (keyPair.getPrivate() instanceof ECKey) {
            return  isValidSecP384R1(ecPublicKey) && isEcSecp384r1Curve((ECKey) keyPair.getPrivate());
        } else {
            return isValidSecP384R1(ecPublicKey)
                    && Crypto.isECPKCS11Key(keyPair.getPrivate()); //can't get curve for PKCS11 keys
        }
    }

    public static boolean isValidSecP384R1(ECPublicKey ecPublicKey) throws GeneralSecurityException {
        if (ecPublicKey == null) {
            log.debug("EC pub key is null");
            return false;
        }

        // it is not possible to create other instance of ECPoint.POINT_INFINITY
        if (ECPoint.POINT_INFINITY.equals(ecPublicKey.getW())) {
            log.debug("EC pub key is infinity");
            return false;
        }

        if (!isEcSecp384r1Curve(ecPublicKey)) {
            log.debug("EC pub key curve OID {} is not secp384r1", getCurveOid(ecPublicKey));
            return false;
        }

        // https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
        // Instead of implementing public key validation, rely on BC validation
        // https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/math/ec/ECPoint.java
        org.bouncycastle.math.ec.ECPoint ecPoint = SECP_384_R_1_CURVE.createPoint(ecPublicKey.getW().getAffineX(),
                ecPublicKey.getW().getAffineY());

        boolean onCurve = ecPoint.isValid();
        if (!onCurve) {
            log.debug("EC pub key is not on secp384r1 curve");
        }
        return onCurve;
    }

    /**
     * Derive EC public key from EC private key (and its curve)
     * @param ecPrivateKey EC private key
     * @return EC KeyPair where public key is derived from ecPrivateKey
     * @throws GeneralSecurityException
     */
    public static KeyPair deriveECPubKeyFromPrivKey(ECPrivateKey ecPrivateKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(getCurveOid(ecPrivateKey));
        org.bouncycastle.math.ec.ECPoint q = spec.getG().multiply(ecPrivateKey.getS());
        PublicKey bcPublicKey = keyFactory.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(q, spec));

        ECPublicKey publicKey = EllipticCurve.forPubKey(bcPublicKey).decodeFromTls(
                ByteBuffer.wrap(encodeEcPubKeyForTls((ECPublicKey) bcPublicKey)));
        return new KeyPair(publicKey, ecPrivateKey);
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
}
