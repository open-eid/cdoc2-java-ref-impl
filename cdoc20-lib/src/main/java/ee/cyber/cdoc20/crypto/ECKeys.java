package ee.cyber.cdoc20.crypto;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EC keys loading, decoding and encoding
 */
public final class ECKeys {
    //https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html#GUID-091BF58C-82AB-4C9C-850F-1660824D5254
    public static final String SECP_384_R_1 = "secp384r1";
    public static final String SECP_384_OID = "1.3.132.0.34";
    public static final String EC_ALGORITHM_NAME = "EC";

    private static final Logger log = LoggerFactory.getLogger(ECKeys.class);

    private ECKeys() {
    }

    public static KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec(SECP_384_R_1));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    @SuppressWarnings("checkstyle:LineLength")
    public static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey) {
        //BigInteger.toByteArray() returns byte in network byte order
        byte[] xBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineX(), Crypto.SECP_384_R_1_LEN_BYTES);
        byte[] yBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineY(), Crypto.SECP_384_R_1_LEN_BYTES);

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

    public static ECPublicKey decodeEcPublicKeyFromTls(ByteBuffer encoded) throws InvalidParameterSpecException, NoSuchAlgorithmException, InvalidKeySpecException {
        return decodeEcPublicKeyFromTls(Arrays.copyOfRange(encoded.array(), encoded.position(), encoded.limit()));
    }

    /**
     * Decode EcPublicKey from TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param encoded EC public key octets encoded as in TLS 1.3 format
     * @return decoded ECPublicKey
     * @throws InvalidParameterSpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static ECPublicKey decodeEcPublicKeyFromTls(byte[] encoded)
            throws InvalidParameterSpecException, NoSuchAlgorithmException, InvalidKeySpecException {

        final int expectedLength = Crypto.SECP_384_R_1_LEN_BYTES;
        if (encoded.length != (2 * expectedLength + 1)) {
            String encodedHex = HexFormat.of().formatHex(encoded);
            log.error("Invalid pubKey len {}, expected {}, encoded: {}", encoded.length, (2 * expectedLength + 1),
                    encodedHex);
            throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
        }

        if (encoded[0] != 0x04) {
            String encodedHex = HexFormat.of().formatHex(encoded);
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
        return (ECPublicKey) KeyFactory.getInstance(EC_ALGORITHM_NAME).generatePublic(pubECSpec);
    }

    private static byte[] toUnsignedByteArray(BigInteger bigInteger, int len) {
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
    public static ECPrivateKey loadECPrivateKey(String openSslPem)
            throws GeneralSecurityException, IOException {

        KeyPair keyPair = loadFromPem(openSslPem);
        if (!isECSecp384r1(keyPair)) {
            throw new IllegalArgumentException("Not EC key pair");
        }

        return (ECPrivateKey)keyPair.getPrivate();
    }

    /**
     * openssl ec -in key.pem -pubout -out public.pem
     * <code>
     * -----BEGIN PUBLIC KEY-----
     * MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhEZdaw/m5tmqIrhonGPKG0ZHLPo7fJLO
     * IwtYw/3/xEPCnRWKyfisJzOkfKyF6g51JyyRYhdzsw6bvE1I1Tr3V4M0C/p+u0Ii
     * 3cnq0xOn+boyF6FzZGQfDtpF/97wA7gw
     * -----END PUBLIC KEY-----
     * <code/>
     *
     * ASN.1:
     * <pre>
         SEQUENCE (2 elem)
           SEQUENCE (2 elem)
               OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
               OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
           BIT STRING (776 bit) 0000010001111001011000011010011100101001101001111001000111111000011010…
     * </pre>
     * @param openSslPem
     * @return
     */
    public static ECPublicKey loadECPublicKey(String openSslPem)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        Pattern pattern = Pattern.compile("(?s)-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----");
        Matcher matcher = pattern.matcher(openSslPem);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Public key not found");
        }
        String pubKeyPem = matcher.group()
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        //SEQUENCE (2 elem)
        //  SEQUENCE (2 elem)
        //      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
        //      OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
        //  BIT STRING (776 bit) 0000010001111001011000011010011100101001101001111001000111111000011010…
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKeyPem));
        ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(x509EncodedKeySpec);
        return ecPublicKey;
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

    public static boolean isEcSecp384r1Curve(ECKey key)
            throws GeneralSecurityException {

    //https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html#GUID-091BF58C-82AB-4C9C-850F-1660824D5254
    // Table 4-28 Recommended Curves Provided by the SunEC Provider
        final String[] secp384r1Names = {SECP_384_OID, SECP_384_R_1, "NIST P-384"};
        String oid = getCurveOid(key);
        return Arrays.asList(secp384r1Names).contains(oid);
    }

    /**
     * Load EC key pair from OpenSSL generated PEM file:
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * Example key PEM:
     * <pre>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </pre>
     * Decoded PEM has ASN.1 structure:
     * <pre>
     SEQUENCE (4 elem)
     INTEGER 1
     OCTET STRING (48 byte) 61D54013F37D8D876657BDD73925B36FDC1704652624F747AC52448F1668365C4BA803…
     [0] (1 elem)
     OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
     [1] (1 elem)
     BIT STRING (776 bit) 0000010010000100010001100101110101101011000011111110011011100110110110…
     </pre>
     *
     * @param pem OpenSSL generated EC private key in PEM
     * @return EC KeyPair decoded from PEM
     */
    public static KeyPair loadFromPem(String pem)
            throws GeneralSecurityException, IOException {

        Object parsed = new PEMParser(new StringReader(pem)).readObject();
        KeyPair pair = new JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair)parsed);
        if (!isECSecp384r1(pair)) {
            throw new IllegalArgumentException("Not EC keypair with secp384r1 curve");
        }
        return pair;
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

        ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
        return isEcSecp384r1Curve(ecPrivateKey) && isEcSecp384r1Curve(ecPublicKey);
    }

    /**
     * Read file contents into String
     * @param file file to read
     * @return file contents as String
     * @throws IOException
     */
    public static String readAll(File file) throws IOException {

        return Files.readString(file.toPath());
    }


    /**
     * Load EC key pair from OpenSSL generated PEM file:
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * Example key PEM:
     * <pre>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </pre>
     * @param pemFile OpenSSL generated EC private key in PEM
     * @return EC KeyPair decoded from PEM
     */
    public static KeyPair loadFromPem(File pemFile)
            throws GeneralSecurityException, IOException {

        return loadFromPem(readAll(pemFile));
    }

    public static ECPublicKey loadECPubKey(File pubPemFile)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        return loadECPublicKey(readAll(pubPemFile));
    }

    public static List<ECPublicKey> loadECPubKeys(File[] pubPemFiles)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

        List<ECPublicKey> list = new LinkedList<>();
        for (File f: pubPemFiles) {
            list.add(loadECPubKey(f));
        }
        return list;
    }
}
