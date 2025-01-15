package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.mobileid.MobileIdClient;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties;
import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.MobileIdClientConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.Properties;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_CAPSULES_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.KEY_SHARES_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.MOBILE_ID_PROPERTIES;
import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.SMART_ID_PROPERTIES;

/**
 * Initialize Services from properties.
 * Checks if following properties are defined and initializes services accordingly:
 * <ul>
 *     <li>{@link Cdoc2ConfigurationProperties#KEY_CAPSULES_PROPERTIES}</li>
 *     <li>{@link Cdoc2ConfigurationProperties#KEY_SHARES_PROPERTIES}</li>
 *     <li>{@link Cdoc2ConfigurationProperties#MOBILE_ID_PROPERTIES}</li>
 *     <li>{@link Cdoc2ConfigurationProperties#SMART_ID_PROPERTIES}</li>
 * </ul>
 *
 * For example define following properties:
 * <pre
 *       smart-id.properties=classpath:smart-id/smart_id-test.properties
 * </pre>
 * to initialize {@code SmartIdClient}
 * <pre>
 * {@code
 * Properties propLocations = new Properties();
 * propLocations.setProperty("smart-id.properties", "classpath:smart-id/smart_id-test.properties");
 * Services services = Cdoc2Services.initFromProperties(propLocations);
 * SmartIdClient sidClient = services.get(SmartIdClient.class);
 * }
 * </pre>

 */
public final class Cdoc2Services {

    private static final Logger log = LoggerFactory.getLogger(Cdoc2Services.class);

    private final Properties propertiesLocations;


    private Cdoc2Services(Properties propertiesLocations) {
        this.propertiesLocations = propertiesLocations;
    }

    /**
     * Initialize Services from properties
     * @param propertiesLocations defines property locations in properties
     * @return Service initialized from properties
     * @throws GeneralSecurityException
     */
    public static Services initFromProperties(Properties propertiesLocations) throws GeneralSecurityException {
        return new Cdoc2Services(propertiesLocations).init();
    }

    /**
     * Read property locations from System properties
     * @return Services initialized from System properties
     * @throws GeneralSecurityException
     */
    public static Services initFromSystemProperties() throws GeneralSecurityException {
        return new Cdoc2Services(System.getProperties()).init();
    }

    public Services init() throws GeneralSecurityException {
        ServicesBuilder services = new ServicesBuilder();
        if (isPropertyDefined(SMART_ID_PROPERTIES)) {
            log.info("Initializing Smart-ID client from {}",
                propertiesLocations.getProperty(SMART_ID_PROPERTIES));
            var config = SmartIdClientConfiguration.load(loadFromPropertyValue(SMART_ID_PROPERTIES));
            services.registerService(SmartIdClient.class,
                ServiceTemplate.service(config, SmartIdClient::new), null);
        }

        if (isPropertyDefined(KEY_SHARES_PROPERTIES)) {
            log.info("Initializing KeyShareClientFactory from {}",
                propertiesLocations.getProperty(KEY_SHARES_PROPERTIES));
            var config = KeySharesConfiguration.load(loadFromPropertyValue(KEY_SHARES_PROPERTIES));
            services.register(KeyShareClientFactory.class, KeySharesClientHelper.createFactory(config), null);
        }

        if (isPropertyDefined(KEY_CAPSULES_PROPERTIES)) {
            log.info("Initializing KeyCapsuleClientFactory from {}",
                propertiesLocations.getProperty(KEY_CAPSULES_PROPERTIES));
            var config = KeyCapsuleClientConfiguration.load(loadFromPropertyValue(KEY_CAPSULES_PROPERTIES));
            services.register(KeyCapsuleClientFactory.class,
                KeyCapsuleClientImpl.createFactory(config), null);
        }

        if (isPropertyDefined(MOBILE_ID_PROPERTIES)) {
            log.info("Initializing Mobile-ID client from {}", propertiesLocations.getProperty(MOBILE_ID_PROPERTIES));
            var config = MobileIdClientConfiguration.load(loadFromPropertyValue(MOBILE_ID_PROPERTIES));
            services.registerService(MobileIdClient.class,
                ServiceTemplate.service(config, MobileIdClient::new), null);
        }

        return services.build();
    }

    private boolean isPropertyDefined(String propertyName) {
        return propertiesLocations.containsKey(propertyName);
    }

    /**
     * Read properties file location from propertyName and load it using PropertiesLoader
     * For example, define following properties:
     *  smart-id.properties=classpath:smart-id/smart_id-test.properties
     * and call {@code loadFromProperty("smart-id.properties")}
     * @param propertyName property that value defined propertiesFilePath
     * @return Properties loaded from
     */
    private Properties loadFromPropertyValue(String propertyName) {
        String propertiesFilePath = propertiesLocations.getProperty(propertyName);
        return PropertiesLoader.loadProperties(propertiesFilePath);
    }

}
