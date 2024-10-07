package ee.cyber.cdoc2.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.Resources;


/**
 * General loader for configuration properties
 */
public final class PropertiesLoader {

    private PropertiesLoader() { }

    /**
     * Gets loaded properties from resource file.
     *
     * @param propertiesFilePath property file location path
     * @throws ConfigurationLoadingException if failed to load properties from resource file
     */
    public static Properties loadProperties(String propertiesFilePath)
        throws ConfigurationLoadingException {

        try (InputStream input = Resources.getResourceAsStream(
            propertiesFilePath, PropertiesLoader.class.getClassLoader()
        )) {
            ensurePropertyResourceIsPresent(input, propertiesFilePath);

            Properties properties = new Properties();
            properties.load(input);
            return properties;
        } catch (IOException ex) {
            throw new ConfigurationLoadingException(
                "Failed to read \"" + propertiesFilePath + "\" properties"
            );
        }
    }

    private static void ensurePropertyResourceIsPresent(InputStream input, String filename)
        throws ConfigurationLoadingException {

        if (null == input) {
            throw new ConfigurationLoadingException(
                "Configuration properties '" + filename + "' are missing."
            );
        }
    }

}
