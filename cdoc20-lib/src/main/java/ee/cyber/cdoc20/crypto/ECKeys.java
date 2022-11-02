package ee.cyber.cdoc20.crypto;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
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
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.crypto.KeyAgreement;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

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

    /**
     * Curve values from {@link ee.cyber.cdoc20.fbs.recipients.EllipticCurve} defined as enum and mapped to
     * known elliptic curve names and oid's
     */
    public enum EllipticCurve {
        UNKNOWN(ee.cyber.cdoc20.fbs.recipients.EllipticCurve.UNKNOWN, null, null),
        secp384r1(ee.cyber.cdoc20.fbs.recipients.EllipticCurve.secp384r1, SECP_384_R_1, SECP_384_OID);

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
                case secp384r1:
                    return isValidSecP384R1(key);
                default:
                    throw new IllegalStateException("isValidKey not implemented for " + this);
            }
        }

        public boolean isValidKeyPair(KeyPair keyPair) throws GeneralSecurityException {
            switch (this) {
                case secp384r1:
                    return isECSecp384r1(keyPair);
                default:
                    throw new IllegalStateException("isValidKeyPair not implemented for " + this);
            }
        }

        /**Key length in bytes. For secp384r1, its 384/8=48*/
        public int getKeyLength() {
            switch (this) {
                case secp384r1:
                    return SECP_384_R_1_LEN_BYTES;
                default:
                    throw new IllegalStateException("getKeyLength not implemented for " + this);
            }
        }

        public ECPublicKey decodeFromTls(ByteBuffer encoded) throws GeneralSecurityException {
            switch (this) {
                case secp384r1:
                    // calls also isValidSecP384R1
                    return decodeSecP384R1EcPublicKeyFromTls(encoded);
                default:
                    throw new IllegalStateException("decodeFromTls not implemented for " + this);
            }
        }

        public KeyPair generateEcKeyPair() throws GeneralSecurityException {
            return ECKeys.generateEcKeyPair(this.getName());
        }

        public static EllipticCurve forName(String name) throws NoSuchAlgorithmException {
            if (SECP_384_R_1.equalsIgnoreCase(name)) {
                return secp384r1;
            }
            throw new NoSuchAlgorithmException("Unknown curve name " + name);
        }

        public static EllipticCurve forOid(String oid) throws NoSuchAlgorithmException {
            if (SECP_384_OID.equals(oid)) {
                return secp384r1;
            }
            throw new NoSuchAlgorithmException("Unknown EC curve oid " + oid);
        }

        public static EllipticCurve forValue(byte value) throws NoSuchAlgorithmException {
            switch (value) {
                case ee.cyber.cdoc20.fbs.recipients.EllipticCurve.secp384r1:
                    return secp384r1;
                default:
                    throw new NoSuchAlgorithmException("Unknown EC curve value " + value);
            }
        }

        /**
         *
         * @param publicKey ECPublicKey
         * @return
         * @throws NoSuchAlgorithmException if publicKey EC curve is not supported
         * @throws InvalidParameterSpecException
         * @throws NoSuchProviderException
         * @throws InvalidKeyException if publicKey is not ECPublicKey
         */
        public static EllipticCurve forPubKey(PublicKey publicKey) throws NoSuchAlgorithmException,
                InvalidParameterSpecException, NoSuchProviderException, InvalidKeyException {

            if (publicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                return forOid(getCurveOid(ecPublicKey));
            } else {
                throw new InvalidKeyException("Unsupported key algorithm " + publicKey.getAlgorithm());
            }
        }

        /**
         * Check if public key is supported by CDOC lib
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

        /**Supported curve names*/
        public static String[] names() {
            return ee.cyber.cdoc20.fbs.recipients.EllipticCurve.names;
        }
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
        if (ecPublicKey.getW() == ECPoint.POINT_INFINITY) {
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

    private static ECPublicKey decodeSecP384R1EcPublicKeyFromTls(ByteBuffer encoded) throws GeneralSecurityException {
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
        if (encoded.length != (2 * expectedLength + 1)) {

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

        KeyPair keyPair = PemTools.loadFromPem(openSslPem);
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

    //https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html#GUID-091BF58C-82AB-4C9C-850F-1660824D5254
    // Table 4-28 Recommended Curves Provided by the SunEC Provider
        final String[] secp384r1Names = {SECP_384_OID, SECP_384_R_1, "NIST P-384"};
        String oid = getCurveOid(key);
        return Arrays.asList(secp384r1Names).contains(oid);
    }

    /**
     * Get KeyStore.ProtectionParameter that gets KeyStore.ProtectionParameter value from user interactively
     * @param prompt Prompt value displayed to user when asking protectionParameter value (ex `PIN:`)
     * @return KeyStore.ProtectionParameter that interactively communicates with user
     */
    public static KeyStore.CallbackHandlerProtection getKeyStoreCallbackProtectionParameter(String prompt) {
       return new KeyStore.CallbackHandlerProtection(callbacks -> {
            for (Callback cp: callbacks) {
                if (cp instanceof PasswordCallback) {
                    // prompt the user for sensitive information
                    PasswordCallback pc = (PasswordCallback)cp;

                    java.io.Console console = System.console();
                    if (console != null) {
                        char[] pin = console.readPassword(prompt);
                        pc.setPassword(pin);
                    } else { //running from IDE, console is null
                        JPasswordField pf = new JPasswordField();
                        int okCxl = JOptionPane.showConfirmDialog(null, pf, prompt,
                                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

                        if (okCxl == JOptionPane.OK_OPTION) {
                            String password = new String(pf.getPassword());
                            pc.setPassword(password.toCharArray());
                        }
                    }
                }
            }
        });
    }

    /**
     * Load KeyPair using automatically generated SunPKCS11 configuration and the default callback to get the pin.
     * Not thread-safe
     *
     * Common openSC library locations:
     * <ul>
     *   <li>For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll,
     *   <li>For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so,
     *   <li>For OSX, it could be /usr/local/lib/opensc-pkcs11.so
     * </ul>
     * @param openScLibPath OpenSC library location, defaults above if null
     * @param slot Slot, default 0
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyPair loadFromPKCS11Interactively(String openScLibPath, Integer slot)
            throws GeneralSecurityException, IOException {

        String pinPrompt;
        if (slot == null) {
            pinPrompt = "PIN1:";
        } else {
            pinPrompt = "PIN" + (slot + 1) + ":";
        }

        KeyStore.CallbackHandlerProtection cbHandlerProtection = getKeyStoreCallbackProtectionParameter(pinPrompt);
        return loadFromPKCS11Interactively(openScLibPath, slot, cbHandlerProtection);
    }

    /**
     * Load KeyPair using automatically generated SunPKCS11 configuration and callback to get the pin. Not thread-safe
     *
     * Common openSC library locations:
     * <ul>
     *   <li>For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll,
     *   <li>For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so,
     *   <li>For OSX, it could be /usr/local/lib/opensc-pkcs11.so
     * </ul>
     * @param openScLibPath OpenSC library location, defaults above if null
     * @param slot Slot, default 0
     * @param cbHandlerProtection the CallbackHandlerProtection used to get the pin interactively
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyPair loadFromPKCS11Interactively(String openScLibPath, Integer slot,
                                                      KeyStore.CallbackHandlerProtection cbHandlerProtection)
            throws IOException, GeneralSecurityException {
        //needs refactor to
        Path confPath = Crypto.createSunPkcsConfigurationFile(null, openScLibPath, slot);
        return loadFromPKCS11Interactively(confPath, cbHandlerProtection);
    }

    /**
     * Load KeyPair using automatically generated SunPKCS11 configuration and callback to get the pin. Not thread-safe
     *
     * Common openSC library locations:
     * <ul>
     *   <li>For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll,
     *   <li>For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so,
     *   <li>For OSX, it could be /usr/local/lib/opensc-pkcs11.so
     * </ul>
     * @param openScLibPath OpenSC library location, defaults above if null
     * @param slot Slot, default 0
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyPair loadFromPKCS11(String openScLibPath, Integer slot, char[] pin)
            throws IOException, GeneralSecurityException {

        Path confPath = Crypto.createSunPkcsConfigurationFile(null, openScLibPath, slot);
        AbstractMap.SimpleEntry<PrivateKey, X509Certificate> pair =
                loadFromPKCS11(confPath, pin, null);
        return new KeyPair(pair.getValue().getPublicKey(), pair.getKey());
    }


    /**
     * Configure SunPKCS11 Provider using configuration file.
     * @param confPath SunPKCS11 configuration file path
     * @return SunPKCS11 Provider initialized from configuration file
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *      SunPKCS11 documentation Table 5-1</a>
     */
    public static Provider initSunPkcs11Provider(Path confPath) {
        log.debug("ECKeys.initSunPkcs11Provider({})", confPath);
        log.info("Configuring SunPKCS11 from {}", confPath.toString());
        Provider sunPkcs11Provider = Security.getProvider("SunPKCS11").configure(confPath.toString());

        log.debug("Provider name {}", sunPkcs11Provider.getName());
        log.debug("Provider info {}", sunPkcs11Provider.getInfo());

        log.debug("Adding provider {}", sunPkcs11Provider);
        Security.addProvider(sunPkcs11Provider);
        log.info("SunPKCS11 provider available under name: {} {}", sunPkcs11Provider.getName(),
                (Security.getProvider(sunPkcs11Provider.getName()) != null));

        return sunPkcs11Provider;
    }

    /**
     * Init OpenSC based KeyStore (like EST-EID). OpenSC must be installed. Creates configuration file for SunPKCS11,
     * configures SunPkcs11 Provider and loads and configures PKCS11 KeyStore from SunPkcs11 Provider.
     *
     * Common openSC library locations:
     * <ul>
     *   <li>For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll,
     *   <li>For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so,
     *   <li>For OSX, it could be /usr/local/lib/opensc-pkcs11.so
     * </ul>
     * @param openScLibPath OpenSC library location, defaults above if null
     * @param slot Slot, default 0
     * @param ksProtection {@link java.security.KeyStore.ProtectionParameter KeyStore.ProtectionParameter},
     *                     example for password: <code>new KeyStore.PasswordProtection("1234".toCharArray())</code> or
     *                     interactive {@link #getKeyStoreCallbackProtectionParameter(String)}
     * @return Configured PKCS11 KeyStore
     * @throws IOException when SunPKCS configuration file creation fails
     * @throws KeyStoreException when KeyStore initialization fails
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyStore initPKCS11KeysStore(String openScLibPath, Integer slot,
                                               KeyStore.ProtectionParameter ksProtection)
            throws IOException, KeyStoreException {
        log.trace("initPKCS11KeysStore");
        Path sunPkcsConPath = Crypto.createSunPkcsConfigurationFile(null, openScLibPath, slot);
        Provider sunPkcs11Provider = initSunPkcs11Provider(sunPkcsConPath);

        return KeyStore.Builder.newInstance("PKCS11", sunPkcs11Provider, ksProtection).getKeyStore();
    }

    /**
     * Load KeyPair using SunPKCS11 configuration and CallbackHandlerProtection. Not thread-safe
     * @param sunPkcs11ConfPath SunPKCS11 configuration location
     * @param cbHandlerProtection the CallbackHandlerProtection used to get the pin interactively
     * @return the KeyPair loaded from PKCS11 device
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyPair loadFromPKCS11Interactively(Path sunPkcs11ConfPath,
                                                      KeyStore.CallbackHandlerProtection cbHandlerProtection)
            throws IOException, GeneralSecurityException {

        AbstractMap.SimpleEntry<PrivateKey, X509Certificate> pair =
                loadFromPKCS11(sunPkcs11ConfPath, null, cbHandlerProtection);
        return new KeyPair(pair.getValue().getPublicKey(), pair.getKey());
    }

    /**
     * Load PrivateKey and Certificate using SunPKCS11 configuration and pin or CallbackHandlerProtection.
     * Not thread-safe
     * @param sunPkcs11ConfPath SunPKCS11 configuration location
     * @param pin pin for reading key from PKCS11
     * @param cbHandlerProtection the CallbackHandlerProtection used to get if pin was provided
     * @return the KeyPair and X509Certificate loaded from PKCS11 device
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static AbstractMap.SimpleEntry<PrivateKey, X509Certificate> loadFromPKCS11(
            Path sunPkcs11ConfPath,
            char[] pin,
            KeyStore.CallbackHandlerProtection cbHandlerProtection) throws IOException, GeneralSecurityException {

        //needs refactor, initPKCS11KeysStore is much cleaner implementation

        if (Crypto.getPkcs11ProviderName() == null) {
            if (!Crypto.initSunPkcs11(sunPkcs11ConfPath)) {
                log.error("Failed to init SunPKCS11 from {}", sunPkcs11ConfPath);
                throw new KeyStoreException("Failed to init SunPKCS11");
            }
        }

        if (Crypto.getPkcs11ProviderName() == null) {
            throw new KeyStoreException("SunPKCS11 not configured or smartcard missing");
        }

        Provider sun = Security.getProvider(Crypto.getPkcs11ProviderName());
        log.debug("{} provider isConfigured={}", sun.getName(), sun.isConfigured());
        log.debug("PKCS11 {}", KeyStore.getInstance("PKCS11", Crypto.getPkcs11ProviderName()).getProvider());
        log.debug("ECDH {}", KeyAgreement.getInstance("ECDH", Crypto.getPkcs11ProviderName()).getProvider());

        KeyStore ks;
        if (cbHandlerProtection == null) {
            if (pin == null) {
                log.warn("PIN not provided");
            }
            ks = KeyStore.getInstance("PKCS11", Crypto.getPkcs11ProviderName());
            ks.load(null, pin);
        } else {
            KeyStore.Builder builder =
                    KeyStore.Builder.newInstance("PKCS11", Crypto.getConfiguredPKCS11Provider(), cbHandlerProtection);
            ks = builder.getKeyStore();
        }

        final List<String> entryNames = new LinkedList<>();
        ks.aliases().asIterator().forEachRemaining(alias -> {
            try {
                log.debug("{} key={} cert={}", alias, ks.isKeyEntry(alias), ks.isCertificateEntry(alias));
                entryNames.add(alias);
            } catch (KeyStoreException e) {
                log.error("KeyStoreException", e);
            }
        });

        if (entryNames.size() != 1) {
            if (entryNames.isEmpty()) {
                log.error("No keys found for {}", Crypto.getPkcs11ProviderName());
            } else {
                log.error("Multiple keys found for {}:{}", Crypto.getPkcs11ProviderName(), entryNames);
            }
            throw new KeyManagementException("No keys or multiple keys found");
        }

        String keyAlias = entryNames.get(0);

        log.info("Loading key \"{}\"", keyAlias);
        KeyStore.PrivateKeyEntry privateKeyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry(keyAlias, cbHandlerProtection);
        if (privateKeyEntry == null) {
            log.error("Entry not found {}", keyAlias);
            throw new KeyStoreException("Key not found for " + keyAlias);
        }

        PrivateKey key = privateKeyEntry.getPrivateKey();
        X509Certificate cert = (X509Certificate) privateKeyEntry.getCertificate();

        log.debug("key class: {}", key.getClass());
        log.debug("key: {}", key);
        log.debug("cert: {} ", cert.getSubjectX500Principal().getName());

        return new AbstractMap.SimpleEntry<>(key, cert);
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
     * Read file contents into String
     * @param file file to read
     * @return file contents as String
     * @throws IOException
     */
    public static String readAll(File file) throws IOException {
        return Files.readString(file.toPath());
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
