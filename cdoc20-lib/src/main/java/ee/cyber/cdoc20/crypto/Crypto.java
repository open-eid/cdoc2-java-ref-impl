package ee.cyber.cdoc20.crypto;

import at.favre.lib.crypto.HKDF;
import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.fbs.header.FMKEncryptionMethod;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.DrbgParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;


public final class Crypto {

    private static final Logger log = LoggerFactory.getLogger(Crypto.class);

    /**
     * SecureRandom instance not to "run out of entropy"
     */
    private static SecureRandom secureRandomInstance = null;

    /**
     * File Master Key length in octets
     */
    public static final int FMK_LEN_BYTES = 256 / 8;

    /**
     * Content Encryption Key length in octets
     */
    public static final int CEK_LEN_BYTES = 256 / 8;

    /**
     * Header HMAC Key length in octets
     */
    public static final int HHK_LEN_BYTES = 256 / 8; //SHA-256

    public static final String HMAC_SHA_256 = "HmacSHA256";

    private static String pkcs11ProviderName;

    private Crypto() {
    }


    public enum OS {
        WINDOWS, LINUX, MAC
    } // Operating systems.



    public static OS getOS() {
        log.debug("os.family: {}, os.name: {}", System.getProperty("os.family"), System.getProperty("os.name"));
        OS os = null;
        String operSys = System.getProperty("os.name").toLowerCase();
        if (operSys.contains("win")) {
            os = OS.WINDOWS;
        } else if (operSys.contains("nix") || operSys.contains("nux")) {
            os = OS.LINUX;
        } else if (operSys.contains("mac")) {
            os = OS.MAC;
        }

        return os;
    }

    /**
     * Create SecureRandom
     * @throws NoSuchAlgorithmException if SecureRandom initialization failed
     */
    private static SecureRandom createSecureRandom() throws NoSuchAlgorithmException {
        log.debug("Initializing SecureRandom");

        //https://www.veracode.com/blog/research/java-crypto-catchup
        SecureRandom sRnd = SecureRandom.getInstance("DRBG", //NIST SP 800-90Ar1
            DrbgParameters.instantiation(
                256, // Required security strength
                PR_AND_RESEED, // configure algorithm to provide prediction resistance and reseeding facilities
                "CDOC20".getBytes() // personalization string, used to derive seed
            )
        );
        log.info("Initialized SecureRandom.");
        return sRnd;
    }


    /**
     * Get SecureRandom instance
     * @return SecureRandom
     * @throws NoSuchAlgorithmException if SecureRandom initialization failed
     */
    public static synchronized SecureRandom getSecureRandom() throws NoSuchAlgorithmException {
        if (secureRandomInstance == null) {
            secureRandomInstance = createSecureRandom();
        }
        return secureRandomInstance;
    }

    public static byte[] generateFileMasterKey() throws NoSuchAlgorithmException {
        byte[] inputKeyingMaterial = new byte[64]; //spec says: ikm should be more than 32bytes of secure random
        getSecureRandom().nextBytes(inputKeyingMaterial);
        return HKDF.fromHmacSha256().extract("CDOC20salt".getBytes(StandardCharsets.UTF_8), inputKeyingMaterial);
    }

    public static SecretKey deriveContentEncryptionKey(byte[] fmk) {
        byte[] cekBytes = HKDF.fromHmacSha256()
                .expand(fmk, "CDOC20cek".getBytes(StandardCharsets.UTF_8), CEK_LEN_BYTES);
        return new SecretKeySpec(cekBytes, "ChaCha20");
    }

    public static SecretKey deriveHeaderHmacKey(byte[] fmk) {
        byte[] hhk = HKDF.fromHmacSha256().expand(fmk, "CDOC20hmac".getBytes(StandardCharsets.UTF_8), HHK_LEN_BYTES);
        return new SecretKeySpec(hhk, HMAC_SHA_256);
    }

    /**
     * Create configuration file for SunPKCS11
     *
     *
     * Common opensc library locations:
     * <ul>
     *   <li>For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll,
     *   <li>For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so,
     *   <li>For OSX, it could be /usr/local/lib/opensc-pkcs11.so
     * </ul>
     * @param name any string, default OpenSC
     * @param openScLibrary OpenSC library location, defaults above
     * @param slot Slot, default 0
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */

    public static Path createSunPkcsConfigurationFile(String name, String openScLibrary, Integer slot) throws
            IOException {
//        name=OpenSC
//        library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
//        slot=0
//        attributes(*,CKO_SECRET_KEY,*) = {
//            CKA_TOKEN = false
//        }


        String newLine = System.getProperty("line.separator");
        Path confPath = Path.of(System.getProperty("java.io.tmpdir")).resolve("opensc-java.cfg");

        String library = openScLibrary;

        if (library == null) {
            library = System.getProperty(CDocConfiguration.OPENSC_LIBRARY_PROPERTY, null);
        }

        if (library == null) {
            OS os = getOS();
            switch (os) {
                case LINUX:
                    library = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
                    break;
                case WINDOWS:
                    library = "C:\\Windows\\SysWOW64\\opensc-pkcs11.dll";
                    break;
                case MAC:
                    library = "/usr/local/lib/opensc-pkcs11.so";
                    break;
                default:
                    log.info("os.family: {}, os.name: {}", System.getProperty("os.family"),
                            System.getProperty("os.name"));
                    throw new IllegalStateException("Unknown OS");
            }
        }

        if ((library == null) || !Files.isReadable(Path.of(library))) {
            log.error("OpenSC library not found at {}, define {} System.property to overwrite ", library,
                    CDocConfiguration.OPENSC_LIBRARY_PROPERTY);
        }

        String slotStr = "";
        if (slot == null) {
            slotStr = "-slot0";
        } else {
            slotStr = "-slot" + slot;
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(bos))) {

            if (name == null) {
                writer.write("name=OpenSC" + slotStr);
            } else {
                writer.write("name=" + name + slotStr);
            }
            writer.newLine();

            writer.write("library=" + library);
            writer.newLine();

            if (slot != null) {
                writer.write("slot=" + slot);
                writer.newLine();
            }

            //est-eid specific
            writer.write("attributes(*,CKO_SECRET_KEY,*) = {"
                    + newLine
                    + "  CKA_TOKEN = false"
                    + newLine
                    + "}");
            writer.newLine();
        }


        String confFileStr = bos.toString(StandardCharsets.UTF_8);

        log.debug("Creating SunPKCS11 configuration file: {}", confPath);
        if (log.isDebugEnabled()) {
            Arrays.asList(confFileStr.split(newLine)).forEach(line -> log.debug(">>{}", line));
        }

        try (BufferedWriter w = Files.newBufferedWriter(confPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
                //StandardOpenOption.DELETE_ON_CLOSE
        )) {
            w.write(confFileStr);
        }

        return confPath;
    }

    /**
     * Configure SunPKCS11 Provider using
     * @param confPath SunPKCS11 configuration file path
     * @return if configuration was successful
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *      SunPKCS11 documentation Table 5-1</a>
     */
    public static boolean initSunPkcs11(Path confPath) {
        log.trace("Crypto.initSunPkcs11({})", confPath);
        log.info("Configuring SunPKCS11 from {}", confPath.toString());
        Provider sunPkcs11Provider = Security.getProvider("SunPKCS11").configure(confPath.toString());

        log.debug("Provider name {}", sunPkcs11Provider.getName());
        log.debug("Provider info {}", sunPkcs11Provider.getInfo());

        // print algorithms available
        //log.debug("Provider properties: {}", sunPkcs11Provider.stringPropertyNames());
        //sunPkcs11Provider.getServices().forEach(s -> log.debug("{} {}",s.getAlgorithm(), s.getType()));

        Security.addProvider(sunPkcs11Provider);
        log.debug("SunPKCS11 provider available under name: {} {}", sunPkcs11Provider.getName(),
                (Security.getProvider(sunPkcs11Provider.getName()) != null));

        try {
            KeyStore ks = KeyStore.getInstance("PKCS11", sunPkcs11Provider);
        } catch (KeyStoreException e) {
            log.error("Successfully configured SunPKCS11, but PKCS11 not found. Is smartcard connected?");
            return false;
        }


        Provider p = getConfiguredPKCS11Provider();
        if (p != null) {
            log.info("Successfully configured PKCS11 provider {}", p.getName());
            return true;
        } else {
            log.error("Configuring PKCS11 provider FAILED");
            return false;
        }
    }

    public static String getPkcs11ProviderName() {

        if (pkcs11ProviderName != null) {
            return pkcs11ProviderName;
        }

        if (System.getProperties().containsKey(CDocConfiguration.PKCS11_PROVIDER_SYSTEM_PROPERTY)) {
            pkcs11ProviderName = System.getProperty(CDocConfiguration.PKCS11_PROVIDER_SYSTEM_PROPERTY);
            return pkcs11ProviderName;
        }

        //[SunPKCS11-OpenSC]
        Provider[] pkcs11ProvidersArr = Security.getProviders("KeyStore.PKCS11");
        List<String> pkcs11Providers = Arrays.stream((pkcs11ProvidersArr == null)
                        ? new Provider[]{} : pkcs11ProvidersArr).map(Provider::getName).toList();
        log.debug("KeyStore.PKCS11 providers {}", pkcs11Providers);

        //[SunEC, SunPKCS11-OpenSC]
        Provider[] ecdhProvidersArr = Security.getProviders("KeyAgreement.ECDH");
        List<String> ecdhProviders = Arrays.stream((ecdhProvidersArr == null) ? new Provider[]{} : ecdhProvidersArr)
                .map(Provider::getName).toList();
        log.debug("KeyAgreement.ECDH {}", ecdhProviders);

        List<String> common = pkcs11Providers.stream().filter(ecdhProviders::contains).toList();

        if (common.size() == 1) {
            pkcs11ProviderName = common.get(0);
            return pkcs11ProviderName;
        } else if (common.size() > 1) {
            log.info("Several PKCS11 providers found that support \"KeyStore.PKCS11\" & \"KeyAgreement.ECDH\": {}",
                    common);
            log.info("Choose correct one by setting system property {} to one of {}",
                    CDocConfiguration.PKCS11_PROVIDER_SYSTEM_PROPERTY, common);
        }

        log.error("PKCS11 provider not configured");
        return null;
    }


    /**
     * Get Provider for PKCS11
     * @return PKCS11 provider or null, if not found or configured
     */
    public static Provider getConfiguredPKCS11Provider() {

        // Name depends on name parameter in configuration file used for initializing SunPKCS11 provider
        Provider sunPKCS11Provider = Security.getProvider(getPkcs11ProviderName());
        if ((sunPKCS11Provider != null) && sunPKCS11Provider.isConfigured()) {
            return sunPKCS11Provider;
        }

        return null;
    }

    public static byte[] calcEcDhSharedSecret(PrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws GeneralSecurityException {

        KeyAgreement keyAgreement;

        // KeyAgreement instances (software and pkcs11) don't work with other provider private keys
        // As pkcs11 loaded key is not instance of ECPrivateKey, then it's possible to differentiate between keys
        // ECPublicKey is always "soft" key
        if (isECPKCS11Key(ecPrivateKey) && (getConfiguredPKCS11Provider() != null)) {
            keyAgreement = KeyAgreement.getInstance("ECDH", getConfiguredPKCS11Provider());
        } else {
            keyAgreement = KeyAgreement.getInstance("ECDH");
        }

        return calcEcDhSharedSecret(keyAgreement, ecPrivateKey, otherPublicKey);
    }


    /**
     * If key is EC PKCS11 key (unextractable hardware key), that should only be used by the provider associated with
     * that token
     * @param key checked
     * @return true if key is EC key from PKCS11 or other hardware provider. Note that !isECPKCS11Key doesn't mean that
     *      the key is EC software key as key might be for some other algorithm
     */
    @SuppressWarnings("checkstyle:LineLength")
    public static boolean isECPKCS11Key(PrivateKey key) {
        // might be manufacturer specif, this true for Manufacturer ID: AS Sertifitseerimiskeskus
        // accessed through opensc-pkcs11
        // .toString(): "SunPKCS11-OpenSC EC private key, 384 bitstoken object, sensitive, unextractable)"
        // .getClass(): sun.security.pkcs11.P11Key$P11PrivateKey

        // https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-508B5E3B-BF39-4E02-A1BD-523352D3AA12
        // Software Key objects (or any Key object that has access to the actual key material) should implement
        // the interfaces in the java.security.interfaces and javax.crypto.interfaces packages (such as DSAPrivateKey).
        //
        // Key objects representing unextractable token keys should only implement the relevant generic interfaces in
        // the java.security and javax.crypto packages (PrivateKey, PublicKey, or SecretKey). Identification of
        // the algorithm of a key should be performed using the Key.getAlgorithm() method.
        // Note that a Key object for an unextractable token key can only be used by the provider associated with that
        // token.



        // algorithm is EC, but doesn't implement java.security.interfaces.ECKey
        return ("EC".equals(key.getAlgorithm()) && !(key instanceof java.security.interfaces.ECKey));
    }

    public static byte[] calcEcDhSharedSecret(KeyAgreement ka, PrivateKey ecPrivateKey, ECPublicKey otherPublicKey)
            throws GeneralSecurityException {

        //log.debug("ECDH provider {}", ka.getProvider());
        ka.init(ecPrivateKey);
        ka.doPhase(otherPublicKey, true);

        //shared secret
        return ka.generateSecret();
    }


    public static byte[] deriveKeyEncryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws GeneralSecurityException {

        return deriveKek(ecKeyPair, otherPublicKey, keyLen, true);
    }

    public static byte[] deriveKeyDecryptionKey(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen)
            throws GeneralSecurityException {
        return deriveKek(ecKeyPair, otherPublicKey, keyLen, false);
    }

    private static byte[] deriveKek(KeyPair ecKeyPair, ECPublicKey otherPublicKey, int keyLen, boolean isEncryptionMode)
            throws GeneralSecurityException {

        byte[] ecdhSharedSecret = calcEcDhSharedSecret(ecKeyPair.getPrivate(), otherPublicKey);
        byte[] kekPm = HKDF.fromHmacSha256()
                .extract("CDOC20kekpremaster".getBytes(StandardCharsets.UTF_8), ecdhSharedSecret);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.writeBytes("CDOC20kek".getBytes(StandardCharsets.UTF_8));
        baos.writeBytes(FMKEncryptionMethod.name(FMKEncryptionMethod.XOR).getBytes(StandardCharsets.UTF_8));

        if (isEncryptionMode) {
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls(otherPublicKey));
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
        } else {
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls((ECPublicKey) ecKeyPair.getPublic()));
            baos.writeBytes(ECKeys.encodeEcPubKeyForTls(otherPublicKey));
        }

        return HKDF.fromHmacSha256().expand(kekPm, baos.toByteArray(), keyLen);
    }

    public static byte[] calcHmacSha256(byte[] fmk, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(deriveHeaderHmacKey(fmk));
        return mac.doFinal(data);
    }

    public static byte[] calcHmacSha256(SecretKey hhk, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(hhk);
        return mac.doFinal(data);
    }


    public static byte[] xor(byte[] x1, byte[] x2) {

        if ((x1 == null) || (x2 == null)) {
            throw new IllegalArgumentException("Cannot xor null value");
        }
        if (x1.length != x2.length) {
            throw new IllegalArgumentException("Array lengths must be equal " + x1.length + "!=" + x2.length);
        }

        byte[] out = new byte[x1.length];
        for (int i = x1.length - 1; i >= 0; i--) {
            out[i] = (byte)(x1[i] ^ x2[i]);
        }
        return out;
    }

}
