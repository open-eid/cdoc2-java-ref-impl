package ee.cyber.cdoc2.config;

import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.util.ConfigurationPropertyUtil;

import static org.junit.jupiter.api.Assertions.assertThrows;


/**
 * Tests for {@link ConfigurationPropertyUtil}.
 */
class ConfigurationPropertyUtilTest {

    private static final Logger log = LoggerFactory.getLogger(ConfigurationPropertyUtilTest.class);

    private static final String PROPERTY_NAME = "propertyName";

    @Test
    void failToLoadClientConfigurationPropertiesWithMissingProperty() {
        Properties properties = setProperty("");

        assertThrows(ConfigurationLoadingException.class, () ->
            ConfigurationPropertyUtil.getRequiredInteger(log, properties, PROPERTY_NAME)
        );

        assertThrows(ConfigurationLoadingException.class, () ->
            ConfigurationPropertyUtil.splitString(log, properties, PROPERTY_NAME)
        );
    }

    @Test
    void failToLoadClientConfigurationPropertiesWithNonNumericalProperty() {
        Properties properties = setProperty("property");

        assertThrows(ConfigurationLoadingException.class, () ->
            ConfigurationPropertyUtil.getRequiredInteger(log, properties, PROPERTY_NAME)
        );
    }

    @Test
    void failToLoadClientConfigurationPropertiesWhenPropertyIsNull() {
        Properties properties = new Properties();
        assertThrows(ConfigurationLoadingException.class, () ->
            ConfigurationPropertyUtil.getRequiredProperty(properties, PROPERTY_NAME)
        );
    }

    private Properties setProperty(String propertyValue) {
        Properties properties = new Properties();
        properties.setProperty(PROPERTY_NAME, propertyValue);

        return properties;
    }

}
