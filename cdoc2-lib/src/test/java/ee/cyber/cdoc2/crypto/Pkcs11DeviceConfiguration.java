package ee.cyber.cdoc2.crypto;

import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.config.PropertiesLoader.loadProperties;
import static ee.cyber.cdoc2.util.ConfigurationPropertyUtil.getRequiredProperty;


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
    public static Pkcs11DeviceConfiguration load() throws ConfigurationLoadingException {
        String filename = System.getProperty("cdoc2.pkcs11.conf-file", "pkcs11-test-idcard.properties");
        return loadFromPropertiesFile(filename);
    }

    private static Pkcs11DeviceConfiguration loadFromPropertiesFile(String fileClasspath)
        throws ConfigurationLoadingException {

        log.info("Loading PKCS11 device configuration from {}", fileClasspath);
        var properties = loadProperties(fileClasspath);

        return new Pkcs11DeviceConfiguration(
            getRequiredProperty(properties, "pkcs11.library"),
            Integer.parseInt(getRequiredProperty(properties, "pkcs11.slot")),
            properties.getProperty("pkcs11.key-alias"),
            getRequiredProperty(properties, "pkcs11.pin").toCharArray(),
            getRequiredProperty(properties, "pkcs11.cert.cn")
        );
    }

}
