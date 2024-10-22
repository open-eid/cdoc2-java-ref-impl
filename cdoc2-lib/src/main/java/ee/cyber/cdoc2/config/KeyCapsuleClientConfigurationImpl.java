package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Key capsule properties loading.
 */
public class KeyCapsuleClientConfigurationImpl implements Cdoc2Configuration {

    private final Properties properties;

    public KeyCapsuleClientConfigurationImpl(Properties properties) {
        this.properties = properties;
    }

    @Override
    public KeyCapsuleClientConfiguration keyCapsuleClientConfiguration()
        throws ConfigurationLoadingException {

        return KeyCapsuleClientConfiguration.load(properties);
    }

}
