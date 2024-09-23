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
        load();
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

    public int getSlot() {
        return slot;
    }

    public char[] getPin() {
        return pin;
    }

    @Nullable
    public String getKeyAlias() {
        return keyAlias;
    }

    public String getCertCn() {
        return certCn;
    }

    /**
     * Loads the PKCS11 device configuration from a file on the classpath.
     * <p>
     * The properties file can be specified with the system property cdoc2.pkcs11.test-configuration
     * e.g -D cdoc2.pkcs11.test-configuration=pkcs11-test-idcard.properties
     */
    private void load() {
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
