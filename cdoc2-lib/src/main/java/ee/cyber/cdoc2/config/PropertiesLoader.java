package ee.cyber.cdoc2.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * General loader for resource properties
 */
public final class PropertiesLoader {

    private PropertiesLoader() { }

    public static Properties loadProperties(String resourceFileClasspath)
        throws ConfigurationLoadingException {

        try (InputStream input
                 = PropertiesLoader.class.getClassLoader().getResourceAsStream(resourceFileClasspath)) {

            Properties properties = new Properties();
            properties.load(input);
            return properties;
        } catch (IOException ex) {
            throw new ConfigurationLoadingException(
                "Failed to load properties from resource file \"" + resourceFileClasspath + "\""
            );
        }
    }

}
