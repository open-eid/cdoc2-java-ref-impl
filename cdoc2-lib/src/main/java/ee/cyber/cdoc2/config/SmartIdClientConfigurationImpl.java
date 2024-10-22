package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Smart ID client properties loading.
 */
public class SmartIdClientConfigurationImpl implements Cdoc2Configuration {

    private final Properties properties;

    public SmartIdClientConfigurationImpl(Properties properties) {
        this.properties = properties;
    }

    @Override
    public SmartIdClientConfiguration smartIdClientConfiguration()
        throws ConfigurationLoadingException {

        return SmartIdClientConfiguration.load(properties);
    }

}
