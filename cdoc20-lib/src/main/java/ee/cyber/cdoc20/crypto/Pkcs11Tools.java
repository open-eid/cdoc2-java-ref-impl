package ee.cyber.cdoc20.crypto;

import ee.cyber.cdoc20.CDocConfiguration;
import ee.cyber.cdoc20.CDocUserException;
import ee.cyber.cdoc20.UserErrorCode;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nullable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.swing.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static ee.cyber.cdoc20.util.OperatingSystem.getOS;

/**
 * Utility class for PKCS11 operations.
 * <p>
 * Common pkcs11 provider library locations:
 * <ul>
 *   <li>For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll,
 *   <li>For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so,
 *   <li>For OSX, it could be /usr/local/lib/opensc-pkcs11.so
 * </ul>
 */
public final class Pkcs11Tools {
    private static final Logger log = LoggerFactory.getLogger(Pkcs11Tools.class);

    private static String pkcs11ProviderName;

    private Pkcs11Tools() {
    }

    /**
     * Load KeyPair using automatically generated SunPKCS11 configuration and the default callback to get the pin.
     * Not thread-safe.
     *
     * @param pkcs11LibPath pkcs11 provider library location, defaults described above if null
     * @param slot the slot number with the keys
     * @param keyAlias key alias (optional) to use in case the are more than one entry in the keystore
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyPair loadFromPKCS11Interactively(String pkcs11LibPath, Integer slot, @Nullable String keyAlias)
            throws GeneralSecurityException, IOException {

        String pinPrompt;
        if (slot == null) {
            pinPrompt = "PIN:";
        } else {
            pinPrompt = "PIN for slot " + slot + ":";
        }

        var entry = loadFromPKCS11(
            createSunPkcsConfigurationFile(null, pkcs11LibPath, slot),
            getKeyStoreProtectionHandler(pinPrompt),
            keyAlias
        );

        return new KeyPair(entry.getValue().getPublicKey(), entry.getKey());
    }

    /**
     * Init OpenSC based KeyStore (like EST-EID). OpenSC must be installed. Creates configuration file for SunPKCS11,
     * configures SunPkcs11 Provider and loads and configures PKCS11 KeyStore from SunPkcs11 Provider.
     *
     * @param openScLibPath OpenSC library location, defaults described above if null
     * @param slot Slot, default 0
     * @param ksProtection {@link KeyStore.ProtectionParameter KeyStore.ProtectionParameter},
     *                     example for password: <code>new KeyStore.PasswordProtection("1234".toCharArray())</code> or
     *                     interactive {@link #getKeyStoreProtectionHandler(String)}
     * @return Configured PKCS11 KeyStore
     * @throws IOException when SunPKCS configuration file creation fails
     * @throws KeyStoreException when KeyStore initialization fails
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    public static KeyStore initPKCS11KeysStore(String openScLibPath, Integer slot,
            KeyStore.ProtectionParameter ksProtection) throws IOException, KeyStoreException {
        log.trace("initPKCS11KeysStore");
        Path sunPkcsConPath = createSunPkcsConfigurationFile(null, openScLibPath, slot);
        initSunPkcs11Provider(sunPkcsConPath);

        return getConfiguredPkcs11KeyStore(ksProtection);
    }

    /**
     * Get Provider for PKCS11
     * @return PKCS11 provider or null, if not found or configured
     */
    public static Provider getConfiguredPKCS11Provider() {
        // Name depends on name parameter in configuration file used for initializing SunPKCS11 provider
        Provider sunPKCS11Provider = Security.getProvider(getPkcs11ProviderName());
        if (sunPKCS11Provider != null && sunPKCS11Provider.isConfigured()) {
            return sunPKCS11Provider;
        }

        return null;
    }

    /**
     * Get KeyStore.ProtectionParameter that gets KeyStore.ProtectionParameter value from user interactively
     * @param prompt Prompt value displayed to user when asking protectionParameter value (e.g `PIN:`)
     * @return KeyStore.ProtectionParameter that interactively communicates with user
     */
    public static KeyStore.CallbackHandlerProtection getKeyStoreProtectionHandler(String prompt) {
        return new KeyStore.CallbackHandlerProtection(callbacks -> {
            for (Callback cp: callbacks) {
                if (cp instanceof PasswordCallback) {
                    // prompt the user for sensitive information
                    PasswordCallback pc = (PasswordCallback) cp;

                    Console console = System.console();
                    if (console != null) {
                        char[] pin = console.readPassword(prompt);
                        pc.setPassword(pin);
                    } else { //running from IDE, console is null
                        JPasswordField pf = new JPasswordField();
                        int result = JOptionPane.showConfirmDialog(null, pf, prompt,
                            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

                        if (result == JOptionPane.OK_OPTION) {
                            String password = new String(pf.getPassword());
                            pc.setPassword(password.toCharArray());
                        } else if (result == JOptionPane.OK_CANCEL_OPTION) {
                            throw new CDocUserException(UserErrorCode.USER_CANCEL, "PIN entry cancelled by user");
                        }
                    }
                }
            }
        });
    }

    static AbstractMap.SimpleEntry<PrivateKey, X509Certificate> loadFromPKCS11(
            Path pkcs11Conf, KeyStore.ProtectionParameter keyProtection, @Nullable String keyAlias)
                throws GeneralSecurityException {

        Provider provider = initSunPkcs11Provider(pkcs11Conf);

        log.debug("{} provider isConfigured={}", provider.getName(), provider.isConfigured());

        var ks = getConfiguredPkcs11KeyStore(keyProtection);

        final List<String> entryNames = new LinkedList<>();
        ks.aliases().asIterator().forEachRemaining(alias -> {
            try {
                log.debug("{} key={} cert={}", alias, ks.isKeyEntry(alias), ks.isCertificateEntry(alias));
                entryNames.add(alias);
            } catch (KeyStoreException e) {
                log.error("KeyStoreException", e);
            }
        });

        if (entryNames.isEmpty()) {
            throw new KeyManagementException("No keys found for " + getPkcs11ProviderName());
        }

        String entryAlias;
        if (entryNames.size() == 1) {
            entryAlias = entryNames.get(0);
        } else {
            if (keyAlias == null) {
                log.info("Multiple key entries found: {}", entryNames);
                throw new KeyStoreException("Multiple entries in keystore but no key alias specified");
            }
            entryAlias = keyAlias;
        }

        log.info("Loading key '{}'", entryAlias);
        KeyStore.PrivateKeyEntry privateKeyEntry =
            (KeyStore.PrivateKeyEntry) ks.getEntry(entryAlias, keyProtection);
        if (privateKeyEntry == null) {
            log.error("Entry not found {}", entryAlias);
            throw new KeyStoreException("Key not found for " + entryAlias);
        }

        PrivateKey key = privateKeyEntry.getPrivateKey();
        X509Certificate cert = (X509Certificate) privateKeyEntry.getCertificate();

        log.debug("key class: {}", key.getClass());
        log.debug("key: {}", key);
        log.debug("cert: {} ", cert.getSubjectX500Principal().getName());

        return new AbstractMap.SimpleEntry<>(key, cert);
    }

    /**
     * Creates a configuration file for SunPKCS11.
     * <p>
     * File example:
     * <pre>
     *     {
     *         name=OpenSC
     *         library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
     *         slot=0
     *         attributes(*,CKO_SECRET_KEY,*) = {
     *              CKA_TOKEN = false
     *         }
     *     }
     * </pre>
     * @param name any string, default OpenSC
     * @param openScLibrary OpenSC library location, defaults described above
     * @param slot Slot, default 0
     * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
     *     SunPKCS11 documentation Table 5-1</a>
     */
    static Path createSunPkcsConfigurationFile(String name, String openScLibrary, Integer slot) throws IOException {
        Path confPath = Path.of(System.getProperty("java.io.tmpdir")).resolve("opensc-java.cfg");

        String library = openScLibrary;

        if (library == null) {
            library = System.getProperty(CDocConfiguration.PKCS11_LIBRARY_PROPERTY, null);
        }

        if (library == null) {
            library = getOpenSCDefaultLocation();
        }

        if (!Files.isReadable(Path.of(library))) {
            log.error(
                "OpenSC library not found at {}, define {} System.property to overwrite ",
                library, CDocConfiguration.PKCS11_LIBRARY_PROPERTY
            );
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
            writer.write("attributes(*,CKO_SECRET_KEY,*) = {");
            writer.newLine();
            writer.write("  CKA_TOKEN = false");
            writer.newLine();
            writer.write("}");
            writer.newLine();
        }

        String confFileStr = bos.toString(StandardCharsets.UTF_8);

        log.debug("Creating SunPKCS11 configuration file: {}", confPath);
        if (log.isDebugEnabled()) {
            log.debug("\n{}", confFileStr);
        }

        try (BufferedWriter w = Files.newBufferedWriter(confPath, StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING)) {
            w.write(confFileStr);
        }

        return confPath;
    }

    private static KeyStore getConfiguredPkcs11KeyStore(KeyStore.ProtectionParameter keyProtection)
            throws KeyStoreException {
        try {
            return KeyStore.Builder
                .newInstance("PKCS11", getConfiguredPKCS11Provider(), keyProtection)
                .getKeyStore();
        } catch (KeyStoreException e) {
            log.error("Failed to get PKCS11 keystore", e);
            handlePkcs11KeyStoreException(e);
            throw e;
        }
    }

    private static synchronized Provider initSunPkcs11Provider(Path confPath) {
        log.debug("initSunPkcs11Provider({})", confPath);
        log.info("Configuring SunPKCS11 from {}", confPath.toString());
        Provider sunPkcs11Provider = Security.getProvider("SunPKCS11").configure(confPath.toString());

        log.debug("Provider info {}", sunPkcs11Provider.getInfo());
        log.debug("Adding provider {}", sunPkcs11Provider);

        // print algorithms available
        //log.debug("Provider properties: {}", sunPkcs11Provider.stringPropertyNames());
        //sunPkcs11Provider.getServices().forEach(s -> log.debug("{} {}",s.getAlgorithm(), s.getType()));

        Security.addProvider(sunPkcs11Provider);
        log.info("SunPKCS11 provider available under name: {} {}", sunPkcs11Provider.getName(),
                Security.getProvider(sunPkcs11Provider.getName()) != null);

        pkcs11ProviderName = sunPkcs11Provider.getName();

        return sunPkcs11Provider;
    }

    private static synchronized String getPkcs11ProviderName() {
        if (pkcs11ProviderName != null) {
            return pkcs11ProviderName;
        }

        if (System.getProperties().containsKey(CDocConfiguration.PKCS11_PROVIDER_SYSTEM_PROPERTY)) {
            pkcs11ProviderName = System.getProperty(CDocConfiguration.PKCS11_PROVIDER_SYSTEM_PROPERTY);
            return pkcs11ProviderName;
        }

        //[SunPKCS11-OpenSC]
        Provider[] pkcs11ProvidersArr = Security.getProviders("KeyStore.PKCS11");
        List<String> pkcs11Providers = Arrays
            .stream(pkcs11ProvidersArr == null ? new Provider[] {} : pkcs11ProvidersArr)
            .map(Provider::getName).toList();
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
        }

        if (common.size() > 1) {
            log.info("Several PKCS11 providers found that support \"KeyStore.PKCS11\" & \"KeyAgreement.ECDH\": {}",
                    common);
            log.info("Choose correct one by setting system property {} to one of {}",
                    CDocConfiguration.PKCS11_PROVIDER_SYSTEM_PROPERTY, common);
        }

        log.error("PKCS11 provider not configured");
        return null;
    }

    private static void handlePkcs11KeyStoreException(KeyStoreException exc) {
        var cause = exc.getCause();

        while (cause != null && cause.getCause() != null) {
            cause = cause.getCause();
        }

        if (cause != null && cause.getMessage() != null) {
            var errorMessage = cause.getMessage();

            if (errorMessage.contains("CKR_PIN_INCORRECT") || errorMessage.contains("CKR_PIN_LEN_RANGE")) {
                throw new CDocUserException(UserErrorCode.WRONG_PIN, errorMessage);
            }
            if (errorMessage.contains("CKR_PIN_LOCKED")) {
                throw new CDocUserException(UserErrorCode.PIN_LOCKED, errorMessage);
            }
            throw new CDocUserException(UserErrorCode.SMART_CARD_NOT_PRESENT, exc.getMessage());
        }
    }

    private static String getOpenSCDefaultLocation() {
        switch (getOS()) {
            case LINUX:
                return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
            case WINDOWS:
                return "C:\\Windows\\SysWOW64\\opensc-pkcs11.dll";
            case MAC:
                return "/usr/local/lib/opensc-pkcs11.so";
            default:
                throw new IllegalStateException("Unknown OS");
        }
    }
}
