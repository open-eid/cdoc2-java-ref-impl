package ee.cyber.cdoc20.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EC keys loading, decoding and encoding
 */
public final class ECKeys {
    public static final String SECP_384_R_1 = "secp384r1";
    private static final Logger log = LoggerFactory.getLogger(ECKeys.class);

    private ECKeys() {
    }

    public static KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
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
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(SECP_384_R_1));

        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubECSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(pubECSpec);
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
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        //https://stackoverflow.com/questions/41927859/how-do-i-load-an-elliptic-curve-pem-encoded-private-key
        // static pkcs8 header for secp384r1
        final byte[] header = HexFormat.of().parseHex("3081bf020100301006072a8648ce3d020106052b810400220481a7");
        //TODO: check that curve in PEM is secp384r1 (After private key, bytes A0 07 06 05 2B 81 04 00 22)

        byte[] der = decodeEcPrivateKeyFromPem(openSslPem);

        byte[] pkcs8 = new byte[header.length + der.length];
        System.arraycopy(header, 0, pkcs8, 0, header.length);
        System.arraycopy(der, 0, pkcs8, header.length, der.length);
        PrivateKey ecPrivate = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        return (ECPrivateKey) ecPrivate;
    }

    /**
     * Decode bytes from OpenSSL PEM
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * Example key.pem:
     * <code>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </code>
     * @param openSslPem OpenSSL generated EC private key in PEM
     * @return pem decoded into bytes (ASN.1 structure)
     */
    private static byte[] decodeEcPrivateKeyFromPem(String openSslPem) {
        Pattern pattern = Pattern.compile("(?s)-----BEGIN EC PRIVATE KEY-----.*-----END EC PRIVATE KEY-----");
        Matcher matcher = pattern.matcher(openSslPem);
        if (!matcher.find()) {
            throw new IllegalArgumentException("EC private key not found");
        }
        String b64 = matcher.group().replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64); //ASN.1 in DER

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
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(x509EncodedKeySpec);
    }

    /**
     * Load EC public key from OpenSSL private key PEM
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
     * Return sequence last element as ECPublicKey
     * @param openSslPem OpenSSL generated EC private key in PEM
     * @return ECPublicKey decoded from PEM
     */
    @SuppressWarnings("java:S1066") //S1066 - Collapsible "if" statements should be merged
    private static ECPublicKey loadECPubKeyFromECPrivKeyPem(String openSslPem)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {

        byte[] raw = decodeEcPrivateKeyFromPem(openSslPem);
        //public key is last 97 bytes in decoded bytes that preceded by length and 0x00
        int pubKeyLen = 2 * Crypto.SECP_384_R_1_LEN_BYTES + 1;
        if (raw.length > pubKeyLen + 2) {
            //public key is preceded by length and 0x00
            if ((raw[raw.length - (pubKeyLen + 2)] == pubKeyLen + 1) //+ preceding 0x00 sign byte
                    && (raw[raw.length - (pubKeyLen + 1)] == 0x00) // preceding 0x00 sign byte
                    && (raw[raw.length - pubKeyLen ] == 0x04)) { //pubKey starts with 0x04

                byte[] encodedPubKey = new byte[pubKeyLen];
                System.arraycopy(raw, raw.length - pubKeyLen, encodedPubKey, 0, pubKeyLen);
                if (log.isDebugEnabled()) {
                    log.debug("PEM pub key part: {}", HexFormat.of().formatHex(encodedPubKey));
                }
                return ECKeys.decodeEcPublicKeyFromTls(encodedPubKey);
            }
        }

        throw new IllegalArgumentException("Illegal EC key");
    }

    /**
     * Load EC keys generated using openssl
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * openssl ec -in key.pem -pubout -out public.pem
     * @param pubKeyPem
     * @param ecPrivatePem
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static KeyPair loadFromPem(String pubKeyPem, String ecPrivatePem)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey ecPrivate = loadECPrivateKey(ecPrivatePem);
        ECPublicKey ecPublicKey = loadECPublicKey(pubKeyPem);
        return new KeyPair(ecPublicKey, ecPrivate);
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
     * @param pem OpenSSL generated EC private key in PEM
     * @return EC KeyPair decoded from PEM
     */
    public static KeyPair loadFromPem(String pem)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
        PrivateKey ecPrivate = loadECPrivateKey(pem);
        ECPublicKey ecPublicKey = loadECPubKeyFromECPrivKeyPem(pem);
        return new KeyPair(ecPublicKey, ecPrivate);
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
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException, IOException {

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
