package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Key shares properties loading.
 */
public class KeySharesConfigurationImpl implements Cdoc2Configuration {

    private final Properties properties;

    public KeySharesConfigurationImpl(Properties properties) {
        this.properties = properties;
    }

    @Override
    public KeySharesConfiguration keySharesConfiguration()
        throws ConfigurationLoadingException {

        return KeySharesConfiguration.load(properties);
    }

}
