package ee.cyber.cdoc2.crypto;

import java.io.File;
import java.io.InputStream;
import java.util.Optional;
import java.util.Properties;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.util.Resources;


/**
 * Test configuration for running PKCS11 tests using a hardware device.
 */
public class Pkcs11DeviceConfiguration {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11DeviceConfiguration.class);

    public Pkcs11DeviceConfiguration() {
        this.loadInternal();
    }

    private String pkcs11Library;
    // the PKCS11 device slot
    private int slot;
    // alias of the key in the keystore to use (if multiple keys in the keystore)
    private @Nullable String keyAlias;
    // the keystore pin
    private char[] pin;
    // part of the CN field in the certificate
    private String certCn;

    public String getPkcs11Library() {
        return pkcs11Library;
    }

    @Deprecated(since = "2.0.1")
    public String pkcs11Library() {
        return getPkcs11Library();
    }

    public int getSlot() {
        return slot;
    }

    @Deprecated(since = "2.0.1")
    public int slot() {
        return getSlot();
    }

    public char[] getPin() {
        return pin;
    }

    @Deprecated(since = "2.0.1")
    public char[] pin() {
        return getPin();
    }

    @Nullable
    public String getKeyAlias() {
        return keyAlias;
    }

    @Deprecated(since = "2.0.1")
    public String keyAlias() {
        return getKeyAlias();
    }

    public String getCertCn() {
        return certCn;
    }

    @Deprecated(since = "2.0.1")
    public String certCn() {
        return getCertCn();
    }

    /**
     * @deprecated Use {@link #Pkcs11DeviceConfiguration()} instead.
     */
    @Deprecated(since = "2.0.1")
    public static Pkcs11DeviceConfiguration load() {
        return new Pkcs11DeviceConfiguration();
    }

    /**
     * Loads the PKCS11 device configuration from a file on the classpath.
     * <p>
     * The properties file can be specified with the system property cdoc2.pkcs11.test-configuration
     * e.g -D cdoc2.pkcs11.test-configuration=pkcs11-test-idcard.properties
     */
    private void loadInternal() {
        final String classpath = "classpath:";
        String filename = System.getProperty(
            "cdoc2.pkcs11.conf-file",
            classpath + "pkcs11-test-idcard.properties"
        );
        String propertyFileName;
        if (filename.contains(classpath)) {
            propertyFileName = filename;
        } else {
            propertyFileName = new File(filename).getAbsolutePath();
        }
        loadFromPropertiesFile(propertyFileName);
    }

    private void loadFromPropertiesFile(String filename) {
        log.info("Loading PKCS11 device configuration from {}", filename);

        try (InputStream is
                 = Resources.getResourceAsStream(filename, Pkcs11Test.class.getClassLoader())) {
            var properties = new Properties();
            properties.load(is);

            init(
                getRequiredProperty(properties, "pkcs11.library"),
                Integer.parseInt(getRequiredProperty(properties, "pkcs11.slot")),
                properties.getProperty("pkcs11.key-alias"),
                getRequiredProperty(properties, "pkcs11.pin").toCharArray(),
                getRequiredProperty(properties, "pkcs11.cert.cn")
            );
        } catch (Exception e) {
            log.error("Failed to read pkcs11 device properties", e);
            throw new RuntimeException(e);
        }
    }

    private void init(
        String xPkcs11Library,
        int xSlot,
        String xKeyAlias,
        char[] xPin,
        String xCertCn
    ) {
        this.pkcs11Library = xPkcs11Library;
        this.slot = xSlot;
        this.keyAlias = xKeyAlias;
        this.pin = xPin;
        this.certCn = xCertCn;
    }

    private String getRequiredProperty(Properties properties, String property) {
        return Optional.ofNullable(properties.getProperty(property))
            .orElseThrow(() -> new IllegalArgumentException("Required property '" + property + "' not found"));
    }

}
