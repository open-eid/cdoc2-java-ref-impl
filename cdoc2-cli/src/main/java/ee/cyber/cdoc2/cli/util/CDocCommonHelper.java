package ee.cyber.cdoc2.cli.util;

import java.io.IOException;
import java.util.Properties;

import ee.cyber.cdoc2.config.ConfigurationProperties;
import ee.cyber.cdoc2.util.Resources;


/**
 * Helper class for common usage.
 */
public final class CDocCommonHelper {

    private CDocCommonHelper() { }

    public static Properties getServerProperties(String keyServerPropertiesFile) throws IOException {
        Properties p = new Properties();
        p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
        return p;
    }

    /**
     * Assigns given values to the system properties for the cdoc2-client
     *
     * @param slot Smart card key slot to use for decrypting
     * @param keyAlias Alias of the keystore entry to use for decrypting
     */
    public static void assignClientConfValuesToSystemProps(
        Integer slot,
        String keyAlias
    ) {
        if (slot != null) {
            System.setProperty(
                ConfigurationProperties.PKCS11_SLOT, String.valueOf(slot)
            );
        }

        if (keyAlias != null) {
            System.setProperty(
                ConfigurationProperties.PKCS11_ALIAS, keyAlias
            );
        }
    }
}
