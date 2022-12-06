package ee.cyber.cdoc20.crypto;

import java.io.InputStream;
import java.util.Optional;
import java.util.Properties;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test configuration for running PKCS11 tests using a hardware device.
 */
public record Pkcs11DeviceConfiguration(
        // full path to the PKCS11 provider library
        String pkcs11Library,

        // the PKCS11 device slot
        int slot,

        // alias of the key in the keystore to use (if multiple keys in the keystore)
        @Nullable String keyAlias,

        // the keystore pin
        char[] pin,

        // part of the CN field in the certificate
        String certCn) {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11DeviceConfiguration.class);

    /**
     * Loads the PKCS11 device configuration from a file on the classpath.
     * <p>
     * The properties file can be specified with the system property cdoc2.pkcs11.test-configuration
     * e.g -D cdoc2.pkcs11.test-configuration=pkcs11-test-idcard.properties
     *
     */
    public static Pkcs11DeviceConfiguration load() {
        String filename = System.getProperty("cdoc2.pkcs11.conf-file", "pkcs11-test-idcard.properties");
        return loadFromPropertiesFile(filename);
    }

    private static Pkcs11DeviceConfiguration loadFromPropertiesFile(String filename) {
        log.info("Loading PKCS11 device configuration from {}", filename);

        try (InputStream is = Pkcs11Test.class.getClassLoader().getResourceAsStream(filename)) {
            var properties = new Properties();
            properties.load(is);

            return new Pkcs11DeviceConfiguration(
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

    private static String getRequiredProperty(Properties properties, String property) {
        return Optional.ofNullable(properties.getProperty(property))
            .orElseThrow(() -> new IllegalArgumentException("Required property '" + property + "' not found"));
    }
}
