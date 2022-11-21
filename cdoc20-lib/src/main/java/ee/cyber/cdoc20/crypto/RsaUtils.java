package ee.cyber.cdoc20.crypto;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Utility class for RSA related functions
 */
public final class RsaUtils {
    private RsaUtils() { }

    /**
     * Init RSA OAEP cipher.
     * @param opMode the operation mode of RSA cipher (this is one of the following: ENCRYPT_MODE, DECRYPT_MODE)
     * @param key RSAPublicKey if opMode is ENCRYPT and RSAPrivateKey for DECRYPT_MODE
     * @return initialized to RsaOAEP Cipher
     * @throws GeneralSecurityException if cipher initialization failed
     */
    private static Cipher getRsaOaepCipher(int opMode, RSAKey key) throws GeneralSecurityException {

        final String rsaOaepTransformation = "RSA/ECB/OAEPPadding";
        // OAEP algorithm padding specifier string from
        // https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-paddings
        // is not enough as standard name doesn't specify if the hash should also be used for Mask Generation Function
        // (MGF1) or should default be used (SHA-1). As a result SunJCE and BC are not compatible for
        // "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" as SunJCE uses MGF param sha1 and BC sha256
        // https://stackoverflow.com/questions/32161720/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
        OAEPParameterSpec oaepParams =
                new OAEPParameterSpec("SHA-256",
                        "MGF1", new MGF1ParameterSpec("SHA-256"),
                        PSource.PSpecified.DEFAULT); //DEFAULT is new byte[0], equal to pSpecified Empty from Spec
        Cipher rsaOaepCipher = Cipher.getInstance(rsaOaepTransformation);
        rsaOaepCipher.init(opMode, (Key) key, oaepParams);
        return rsaOaepCipher;
    }

    /**
     * Encrypt plain with rsaPublicKey
     * @param plain data to encrypted with rsaPublicKey
     * @param rsaPublicKey key to use for encryption
     * @return encrypted data
     * @throws GeneralSecurityException if encryption failed
     */
    public static byte[] rsaEncrypt(byte[] plain, RSAPublicKey rsaPublicKey) throws GeneralSecurityException {

        Cipher rsa = getRsaOaepCipher(Cipher.ENCRYPT_MODE, rsaPublicKey);
        return rsa.doFinal(plain);
    }

    /**
     * Decrypt encrypted with rsaPrivateKey
     * @param encrypted data rsaPrivateKey matching public RSA key
     * @param rsaPrivateKey key to use for decryption
     * @return decrypted data
     * @throws GeneralSecurityException if decryption failed
     */
    public static byte[] rsaDecrypt(byte[] encrypted, RSAPrivateKey rsaPrivateKey) throws GeneralSecurityException {

        Cipher rsa = getRsaOaepCipher(Cipher.DECRYPT_MODE, rsaPrivateKey);
        return rsa.doFinal(encrypted);
    }

    /**
     * Encode RSA public key as in RFC8017 RSA Public Key Syntax (A.1.1) https://www.rfc-editor.org/rfc/rfc8017#page-54
     * <pre>
     *           RSAPublicKey ::= SEQUENCE {
     *              modulus           INTEGER,  -- n
     *              publicExponent    INTEGER   -- e
     *          }
     * </pre>
     * See RsaTest.java for examples
     * @return rsaPublicKey encoded as ASN1 RSAPublicKey
     */
    public static byte[] encodeRsaPubKey(RSAPublicKey rsaPublicKey) {
        Objects.requireNonNull(rsaPublicKey);

        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(new ASN1Integer(rsaPublicKey.getModulus()));
        v.add(new ASN1Integer(rsaPublicKey.getPublicExponent()));
        DERSequence derSequence = new DERSequence(v);
        try {
            return derSequence.getEncoded();
        } catch (IOException io) {
            // getEncoded uses internally ByteArrayOutputStream that shouldn't throw IOException
            throw new IllegalStateException("Failed to encode rsaPublicKey", io);
        }
    }

    /**
     * Decode RSA public key from byte stream as defined in
     * RFC8017 RSA Public Key Syntax (A.1.1) https://www.rfc-editor.org/rfc/rfc8017#page-54
     * <pre>
     *           RSAPublicKey ::= SEQUENCE {
     *              modulus           INTEGER,  -- n
     *              publicExponent    INTEGER   -- e
     *          }
     * </pre>
     * @param asn1Data asn1 sequence containing RSAPublicKey structure
     * @return decoded RSA public key
     * @throws IOException if decoding fails
     * @throws GeneralSecurityException if converting ASN1 data to RSA public key fails
     * see RsaTest.java for examples
     */
    public static RSAPublicKey decodeRsaPubKey(byte[] asn1Data) throws IOException, GeneralSecurityException {

        ASN1Primitive p = ASN1Primitive.fromByteArray(asn1Data);
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(p);

        if (asn1Sequence.size() != 2) {
            throw new IOException("Bad sequence size: " + asn1Sequence.size());
        }

        ASN1Integer mod = ASN1Integer.getInstance(asn1Sequence.getObjectAt(0));
        ASN1Integer exp = ASN1Integer.getInstance(asn1Sequence.getObjectAt(1));

        RSAPublicKeySpec spec = new RSAPublicKeySpec(mod.getPositiveValue(), exp.getPositiveValue());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    public static RSAPublicKey decodeRsaPubKey(ByteBuffer asn1BB) throws GeneralSecurityException, IOException {
        return decodeRsaPubKey(Arrays.copyOfRange(asn1BB.array(), asn1BB.position(), asn1BB.limit()));
    }
}
