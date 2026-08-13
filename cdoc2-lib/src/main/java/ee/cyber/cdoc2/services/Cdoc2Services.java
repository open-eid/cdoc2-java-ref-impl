package ee.cyber.cdoc2.services;

import java.security.GeneralSecurityException;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.AuthClient;
import ee.cyber.cdoc2.client.AuthClientImpl;
import ee.cyber.cdoc2.client.KeyCapsuleClient;
import ee.cyber.cdoc2.client.KeyCapsuleClientFactory;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.RpClient;
import ee.cyber.cdoc2.client.RpClientImpl;
import ee.cyber.cdoc2.config.AuthClientConfiguration;
import ee.cyber.cdoc2.config.ConfigurationProperties;
import ee.cyber.cdoc2.config.RpClientConfiguration;
import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;

import static ee.cyber.cdoc2.config.ConfigurationProperties.*;

/**
 * Initialize Services from properties.
 * Checks if following properties are defined and initializes services accordingly:
 * <ul>
 *     <li>{@link ConfigurationProperties#KEY_CAPSULE_PROPERTIES}</li>
 *     <li>{@link ConfigurationProperties#KEY_CAPSULE_POST_PROPERTIES}</li>
 *     <li>{@link ConfigurationProperties#KEY_SHARES_PROPERTIES}</li>
 *     <li>{@link ConfigurationProperties#AUTH_SERVER_PROPERTIES}</li>
 *     <li>{@link ConfigurationProperties#RP_SERVER_PROPERTIES}</li>
 * </ul>
 * <p>
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
     *
     * @param propertiesLocations defines property locations in properties
     * @return Service initialized from properties
     * @throws GeneralSecurityException
     */
    public static Services initFromProperties(Properties propertiesLocations) throws GeneralSecurityException {
        return new Cdoc2Services(propertiesLocations).init();
    }

    /**
     * Read property locations from System properties
     *
     * @return Services initialized from System properties
     * @throws GeneralSecurityException
     */
    public static Services initFromSystemProperties() throws GeneralSecurityException {
        return new Cdoc2Services(System.getProperties()).init();
    }

    public Services init() throws GeneralSecurityException {
        ServicesBuilder services = new ServicesBuilder();

        // capsule-server GET endpoint for decryption that requires mTLS and may need PIN to access
        // private key on smart-card
        if (isPropertyDefined(KEY_CAPSULE_PROPERTIES)) {
            log.info("Initializing KeyCapsuleClientFactory from {}",
                propertiesLocations.getProperty(KEY_CAPSULE_PROPERTIES));
            var config = KeyCapsuleClientConfiguration.load(loadFromPropertyValue(KEY_CAPSULE_PROPERTIES));
            services.register(KeyCapsuleClientFactory.class,
                KeyCapsuleClientImpl.createFactory(config), null);

            log.info("Initializing KeyCapsuleClient from {}",
                propertiesLocations.getProperty(KEY_CAPSULE_PROPERTIES));
            services.register(KeyCapsuleClient.class,
                KeyCapsuleClientImpl.create(config, false), null);
        }

        // capsule-server post endpoint for encryption that doesn't require mTLS, used for encryption only
        if (isPropertyDefined(KEY_CAPSULE_POST_PROPERTIES)) {
            log.info("Initializing KeyCapsuleClient from {}",
                propertiesLocations.getProperty(KEY_CAPSULE_POST_PROPERTIES));
            var config = KeyCapsuleClientConfiguration.load(loadFromPropertyValue(KEY_CAPSULE_POST_PROPERTIES));
            services.register(KeyCapsuleClient.class,
                KeyCapsuleClientImpl.create(config, false), null);
        }

        // shares-server required for authentication based encryption/decryption.
        // Used for Smart-ID/Mobile-ID encryption/decryption
        if (isPropertyDefined(KEY_SHARES_PROPERTIES)) {
            log.info("Initializing KeyShareClientFactory from {}",
                propertiesLocations.getProperty(KEY_SHARES_PROPERTIES));
            var config = KeySharesConfiguration.load(loadFromPropertyValue(KEY_SHARES_PROPERTIES));
            services.register(KeySharesClientFactory.class, KeySharesClientHelper.createFactory(config), null);
        }

        if (isPropertyDefined(AUTH_SERVER_PROPERTIES)) {
            log.info("Initializing Authentication server client from {}",
                propertiesLocations.getProperty(AUTH_SERVER_PROPERTIES));
            var config = AuthClientConfiguration.load(
                loadFromPropertyValue(AUTH_SERVER_PROPERTIES)
            );
            services.register(AuthClient.class,
                AuthClientImpl.create(config), null);
        }

        if (isPropertyDefined(RP_SERVER_PROPERTIES)) {
            log.info("Initializing RP server client from {}",
                propertiesLocations.getProperty(RP_SERVER_PROPERTIES));
            var config = RpClientConfiguration.load(
                loadFromPropertyValue(RP_SERVER_PROPERTIES)
            );
            services.registerService(RpClient.class,
                ServiceTemplate.service(config, RpClientImpl::create), null);
        }

        return services.build();
    }

    private boolean isPropertyDefined(String propertyName) {
        return propertiesLocations.containsKey(propertyName);
    }

    /**
     * Read properties file location from propertyName and load it using PropertiesLoader
     * For example, define following properties:
     * smart-id.properties=classpath:smart-id/smart_id-test.properties
     * and call {@code loadFromProperty("smart-id.properties")}
     *
     * @param propertyName property that value defined propertiesFilePath
     * @return Properties loaded from
     */
    private Properties loadFromPropertyValue(String propertyName) {
        String propertiesFilePath = propertiesLocations.getProperty(propertyName);
        return PropertiesLoader.loadProperties(propertiesFilePath);
    }

}
