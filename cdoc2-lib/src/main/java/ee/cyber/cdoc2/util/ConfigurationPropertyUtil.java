package ee.cyber.cdoc2.util;

import java.util.HashSet;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

import org.slf4j.Logger;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Utility for validating and converting configuration property to different types.
 */
public final class ConfigurationPropertyUtil {

    private ConfigurationPropertyUtil() { }

    /**
     * Gets configuration property value in string representation.
     *
     * @param properties properties
     * @param propertyName property name
     * @return property value
     * @throws ConfigurationLoadingException if configuration property is missing
     */
    public static String getRequiredProperty(Properties properties, String propertyName)
        throws ConfigurationLoadingException {

        return Optional.ofNullable(properties.getProperty(propertyName))
            .orElseThrow(() -> new ConfigurationLoadingException(
                "Required property '" + propertyName + "' not found")
            );
    }

    /**
     * Gets integer value from the configuration property string representation.
     *
     * @param log logger
     * @param p properties
     * @param propertyName property name
     * @return the integer value of configuration property
     * @throws ConfigurationLoadingException if configuration value is not a valid integer or
     *                                       missing
     */
    public static Integer getRequiredInteger(
        Logger log,
        Properties p,
        String propertyName
    ) throws ConfigurationLoadingException {

        String property = getRequiredProperty(p, propertyName);
        notBlank(log, property, propertyName);

        try {
            return Integer.parseInt(property);
        } catch (NumberFormatException nfe) {
            String errorMsg = String.format(
                "Property \"%s\" value \"%s\" is not a valid number.", propertyName, property
            );
            throw new ConfigurationLoadingException(errorMsg);
        }
    }

    /**
     * Gets integer value from the configuration property if exists.
     *
     * @param log logger
     * @param p properties
     * @param propertyName property name
     * @return the integer value of configuration property
     */
    public static Optional<Integer> getInteger(
        Logger log,
        Properties p,
        String propertyName
    ) {
        try {
            return Optional.ofNullable(p.getProperty(propertyName)).map(Integer::parseInt);
        } catch (NumberFormatException nfe) {
            log.warn(
                "Invalid int value {} for property {}.",
                p.getProperty(propertyName), propertyName
            );
            return Optional.empty();
        }
    }

    /**
     * Gets boolean value from the configuration property if exists.
     *
     * @param p properties
     * @param name property name
     * @return the boolean value of configuration property
     */
    public static Optional<Boolean> getBoolean(Properties p, String name) {
        return Optional.ofNullable(p.getProperty(name)).map(Boolean::parseBoolean);
    }

    /**
     * Gets the set of configuration properties.
     *
     * @param log logger
     * @param p properties
     * @param propertyName property name
     * @return the set of configuration properties
     * @throws ConfigurationLoadingException if configuration value is missing
     */
    public static Set<String> splitString(
        Logger log,
        Properties p,
        String propertyName
    ) throws ConfigurationLoadingException {
        String property = getRequiredProperty(p, propertyName);
        notBlank(log, property, propertyName);

        Set<String> properties = new HashSet<>();
        String[] splitProperties = property.split(",");
        for (String splitProperty : splitProperties) {
            String propertyWithoutWhitespaces = splitProperty.strip();
            properties.add(propertyWithoutWhitespaces);
        }

        return properties;
    }

    /**
     * Validates configuration property.
     *
     * @param log logger
     * @param propertyValue property value in string representation
     * @param propertyName property name
     * @throws ConfigurationLoadingException if configuration value is missing
     */
    public static void notBlank(
        Logger log,
        String propertyValue,
        String propertyName
    ) throws ConfigurationLoadingException {
        if (propertyValue.isBlank()) {
            String errorMsg = String.format(
                "Property \"%s\" value is missing.", propertyName
            );
            log.error(errorMsg);
            throw new ConfigurationLoadingException(errorMsg);
        }
    }

}
