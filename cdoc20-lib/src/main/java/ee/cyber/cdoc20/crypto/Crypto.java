package ee.cyber.cdoc20.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import at.favre.lib.crypto.HKDF;


import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static java.security.DrbgParameters.Capability.PR_AND_RESEED;


public class Crypto {

    private static final Logger log = LoggerFactory.getLogger(Crypto.class);

    public static final String SECP_384_R_1 = "secp384r1";

    /**
     * Key length for secp384r1 curve
     */
    public static final int SECP_384_R_1_LEN_BYTES = 384 / 8;

    /**
     * File Master Key length in octets
     */
    public final static int FMK_LEN_BYTES = 256 / 8;

    /**
     * Content Encryption Key length in octets
     */
    public final static int CEK_LEN_BYTES = 256 / 8;



    /**
     * Header HMAC Key length in octets
     */
    public final static int HHK_LEN_BYTES = 256 / 8; //SHA-256

    public static SecureRandom getSecureRandom() throws NoSuchAlgorithmException {
        //https://www.veracode.com/blog/research/java-crypto-catchup
        return SecureRandom.getInstance("DRBG" , //NIST SP 800-90Ar1
                DrbgParameters.instantiation(256,  // Required security strength
                        PR_AND_RESEED,  // configure algorithm to provide prediction resistance and reseeding facilities
                        "CDOC20".getBytes() // personalization string, used to derive seed not involved in providing entropy.
                )
        );
    }


    public static byte[] generateFileMasterKey() throws NoSuchAlgorithmException {
        byte[] inputKeyingMaterial = new byte[64]; //spec says: ikm should be more than 32bytes of secure random
        getSecureRandom().nextBytes(inputKeyingMaterial);
        byte[] fmk = HKDF.fromHmacSha256().extract("CDOC20salt".getBytes(StandardCharsets.UTF_8), inputKeyingMaterial);
        return fmk;
    }

//    public static byte[] deriveContentEncryptionKey(byte[] fmk) {
//        return HKDF.fromHmacSha256().expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), CEK_LEN_BYTES);
//    }

    public static SecretKey deriveContentEncryptionKey(byte[] fmk) {
        byte[] cekBytes = HKDF.fromHmacSha256().expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), CEK_LEN_BYTES);
        SecretKeySpec secretKeySpec = new SecretKeySpec(cekBytes, "ChaCha20");
        return secretKeySpec;
    }

//    public static byte[] deriveHeaderHmacKey(byte[] fmk) throws NoSuchAlgorithmException {
//        //MessageDigest.getInstance("SHA-256").getDigestLength();
//        return HKDF.fromHmacSha256().expand(fmk, "CDOC20hmac".getBytes(StandardCharsets.UTF_8), HHK_LEN_BYTES);
//    }

    public static SecretKey deriveHeaderHmacKey(byte[] fmk) {
        byte[] hhk = HKDF.fromHmacSha256().expand(fmk, "CDOC20hmac".getBytes(StandardCharsets.UTF_8), HHK_LEN_BYTES);
        return new SecretKeySpec(hhk, "HmacSHA256");
    }


    public static KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");// provider SunEC
        keyPairGenerator.initialize( new ECGenParameterSpec(SECP_384_R_1));

        //System.out.println("EC provider:" + keyPairGenerator.getProvider());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * Encode EcPublicKey in TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param ecPublicKey EC public key
     * @return ecPublicKey encoded in TLS 1.3 EC pub key format
     */
    public static byte[] encodeEcPubKeyForTls(ECPublicKey ecPublicKey) {
        //BigInteger.toByteArray() returns byte in network byte order
        byte[] xBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineX());
        byte[] yBytes = toUnsignedByteArray(ecPublicKey.getW().getAffineY());

        //EC pubKey in TLS 1.3 format
        //https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        //https://github.com/dushitaoyuan/littleca/blob/5694924eb084e2923bb61550c30c0444ddc68484/littleca-core/src/main/java/com/taoyuanx/ca/core/sm/util/BCECUtil.java#L83
        //https://github.com/bcgit/bc-java/blob/526b5846653100fc521c1a68c02dbe9df3347a29/core/src/main/java/org/bouncycastle/math/ec/ECCurve.java#L410
        byte[] tlsPubKey = new byte[1 + xBytes.length + yBytes.length];
        tlsPubKey[0] = 0x04; //uncompressed

        System.arraycopy(xBytes, 0, tlsPubKey, 1, xBytes.length);
        System.arraycopy(yBytes, 0, tlsPubKey,  1 + xBytes.length, yBytes.length);

        return tlsPubKey;
    }

    /**
     * Decode EcPublicKey from TLS 1.3 format https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
     * @param encoded EC public key octets encoded as in TLS 1.3 format
     * @return decoded ECPublicKey
     * @throws InvalidParameterSpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static ECPublicKey decodeEcPublicKeyFromTls(byte[] encoded) throws InvalidParameterSpecException, NoSuchAlgorithmException, InvalidKeySpecException {

        final int expectedLength = SECP_384_R_1_LEN_BYTES;
        if (encoded.length != (2 * expectedLength + 1))
        {
            log.error("Invalid pubKey len {}, expected {}, encoded: {}", encoded.length, (2 * expectedLength + 1),
                    HexFormat.of().formatHex(encoded));
            throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
        }

        if (encoded[0] != 0x04) {
            log.error("Illegal EC pub key encoding. Encoded: {}", HexFormat.of().formatHex(encoded));
            throw new IllegalArgumentException("Invalid encoding" );
        }

        BigInteger X = new BigInteger(1, Arrays.copyOfRange(encoded,1, expectedLength+1));
        log.debug("decoded X {}", HexFormat.of().formatHex(X.toByteArray()));
        BigInteger Y = new BigInteger(1, Arrays.copyOfRange(encoded,expectedLength+1, encoded.length));
        log.debug("decoded Y {}", HexFormat.of().formatHex(Y.toByteArray()));

        ECPoint pubPoint = new ECPoint(X, Y);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(SECP_384_R_1));

        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec pubECSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(pubECSpec);
    }

    public static ECPublicKey decodeEcPublicKeyFromTls(ByteBuffer encoded) throws InvalidParameterSpecException, NoSuchAlgorithmException, InvalidKeySpecException {
        return decodeEcPublicKeyFromTls(Arrays.copyOfRange(encoded.array(), encoded.position(), encoded.limit()));
    }

    private static byte[] toUnsignedByteArray(BigInteger bigInteger) {
        //https://stackoverflow.com/questions/4407779/biginteger-to-byte
        byte[] array = bigInteger.toByteArray();
        int expectedLen = (bigInteger.bitLength() + 7) / 8;
        //log.debug("Crypto::toUnsignedByteArray {}", HexFormat.of().formatHex(array));
        if ((array[0] == 0) && (array.length == expectedLen + 1)) {
            return Arrays.copyOfRange(array, 1, array.length);
        } else {
            if (array.length != expectedLen) {
                log.warn("Expected EC key to be {} bytes, but was {}. bigInteger: {}", expectedLen, array.length, HexFormat.of().formatHex(array));
            }
            return array;
        }
    }

    public static byte[] calcEcDhSharedSecret(ECPrivateKey ecPrivateKey, ECPublicKey otherPublicKey) throws NoSuchAlgorithmException, InvalidKeyException {

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ecPrivateKey);
        ka.doPhase(otherPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        return sharedSecret;
    }

    public static byte[] deriveKeyEncryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen) throws NoSuchAlgorithmException, InvalidKeyException {

        return deriveKek(ecKeyPair, otherPublicKey, keyLen, true);
    }

    public static byte[] deriveKeyDecryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen) throws NoSuchAlgorithmException, InvalidKeyException {
        return deriveKek(ecKeyPair, otherPublicKey, keyLen, false);
    }

    private static byte[] deriveKek(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen, boolean isEncryptionMode) throws NoSuchAlgorithmException, InvalidKeyException {

        byte[] ecdhSharedSecret = calcEcDhSharedSecret((ECPrivateKey) ecKeyPair.getPrivate(), otherPublicKey);
        byte[] kekPm = HKDF.fromHmacSha256().extract("CDOC20kekpremaster".getBytes(StandardCharsets.UTF_8), ecdhSharedSecret);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes("CDOC20kek".getBytes(StandardCharsets.UTF_8));
        baos.writeBytes(FMKEncryptionMethod.name(FMKEncryptionMethod.XOR).getBytes(StandardCharsets.UTF_8));

        if (isEncryptionMode) {
            baos.writeBytes(encodeEcPubKeyForTls(otherPublicKey));
            baos.writeBytes(encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
        } else {
            baos.writeBytes(encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
            baos.writeBytes(encodeEcPubKeyForTls(otherPublicKey));
        }

        return HKDF.fromHmacSha256().expand(kekPm, baos.toByteArray(), keyLen );
    }

    public static byte[] calcHmacSha256(byte[] fmk, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(deriveHeaderHmacKey(fmk));
        return mac.doFinal(data);
    }

    public static byte[] calcHmacSha256(SecretKey hhk, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hhk);
        return mac.doFinal(data);
    }




    public static byte[] xor(byte[] x1, byte[] x2) {

        if ((x1 == null) || (x2 == null)) {
            throw new IllegalArgumentException("Cannot xor null value");
        }
        if (x1.length != x2.length) {
            throw new IllegalArgumentException("Array lengths must be equal "+x1.length+ "!=" +x2.length);
        }
        byte[] out = new byte[x1.length];

        for (int i = x1.length - 1; i >= 0; i--) {
            out[i] = (byte)(x1[i] ^ x2[i]);
        }
        return out;
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
    public static ECPrivateKey loadECPrivateKey(String openSslPem) throws NoSuchAlgorithmException, InvalidKeySpecException {

        //https://stackoverflow.com/questions/41927859/how-do-i-load-an-elliptic-curve-pem-encoded-private-key
        // static pkcs8 header
        final byte[] header = HexFormat.of().parseHex("3081bf020100301006072a8648ce3d020106052b810400220481a7");

        byte[] pem = decodeEcPrivateKeyFromPem(openSslPem);
        byte[] pkcs8 = new byte[header.length + pem.length];
        System.arraycopy(header, 0, pkcs8, 0, header.length);
        System.arraycopy(pem, 0,pkcs8, header.length, pem.length);
        PrivateKey ecPrivate = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        return (ECPrivateKey) ecPrivate;
    }

    /**
     * Decode bytes from OpenSSL PEM
     * openssl ecparam -name secp384r1 -genkey -noout -out key.pem
     * Example:
     * <code>
     * -----BEGIN EC PRIVATE KEY-----
     * MIGkAgEBBDBh1UAT832Nh2ZXvdc5JbNv3BcEZSYk90esUkSPFmg2XEuoA7avS/kd
     * 4HtHGRbRRbagBwYFK4EEACKhZANiAASERl1rD+bm2aoiuGicY8obRkcs+jt8ks4j
     * C1jD/f/EQ8KdFYrJ+KwnM6R8rIXqDnUnLJFiF3OzDpu8TUjVOvdXgzQL+n67QiLd
     * yerTE6f5ujIXoXNkZB8O2kX/3vADuDA=
     * -----END EC PRIVATE KEY-----
     * </code>
     * @param openSslPem OpenSSL generated EC private key in PEM
     * @return pem decoded into bytes
     */
    private static byte[] decodeEcPrivateKeyFromPem(String openSslPem) {
        Pattern pattern = Pattern.compile("(?s)-----BEGIN EC PRIVATE KEY-----.*-----END EC PRIVATE KEY-----");
        Matcher matcher = pattern.matcher(openSslPem);
        if (!matcher.find()) {
            throw new IllegalArgumentException("EC private key not found");
        }
        String strippedPem = matcher.group().replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] pem = Base64.getDecoder().decode(strippedPem); //? is it actually x509 or ASN.1 ?
        return pem;
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
     * @param openSslPem
     * @return
     */
    public static ECPublicKey loadECPublicKey(String openSslPem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Pattern pattern = Pattern.compile("(?s)-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----");
        Matcher matcher = pattern.matcher(openSslPem);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Public key not found");
        }
        String pubKeyPem = matcher.group()
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

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
     * @param openSslPem OpenSSL generated EC private key in PEM
     * @return ECPublicKey decoded from PEM
     */
    private static ECPublicKey loadECPubKeyFromOpenSslPem(String openSslPem) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {

        byte[] raw = decodeEcPrivateKeyFromPem(openSslPem);

        //FIXME: hackish code, find format spec for PEM generated by OpenSSL
        //public key is last 97 bytes in decoded bytes that preceded by length and 0x00
        int pubKeyLen = 2 * SECP_384_R_1_LEN_BYTES + 1;
        if (raw.length > pubKeyLen + 2) {
            //public key is preceded by length and 0x00
            if ((raw[raw.length - (pubKeyLen + 2)] == pubKeyLen+1) //+ preceding 0x00
                    && (raw[raw.length - (pubKeyLen + 1)] == 0x00)
                    && (raw[raw.length - pubKeyLen ] == 0x04)) { //pubKey starts with 0x04

                byte[] encodedPubKey = new byte[pubKeyLen];
                System.arraycopy(raw, raw.length - pubKeyLen, encodedPubKey, 0, pubKeyLen);
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedPubKey);
                log.debug("PEM pub key part: {}", HexFormat.of().formatHex(encodedPubKey));
                return decodeEcPublicKeyFromTls(encodedPubKey);
                //return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(x509EncodedKeySpec);
            }
        }

        //log.error("Unable to decode EC public key from {}", HexFormat.of().formatHex(raw));
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
    public static KeyPair loadFromPem(String pubKeyPem, String ecPrivatePem) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
    public static KeyPair loadFromPem(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
        PrivateKey ecPrivate = loadECPrivateKey(pem);
        ECPublicKey ecPublicKey = loadECPubKeyFromOpenSslPem(pem);
        return new KeyPair(ecPublicKey, ecPrivate);
    }
}
