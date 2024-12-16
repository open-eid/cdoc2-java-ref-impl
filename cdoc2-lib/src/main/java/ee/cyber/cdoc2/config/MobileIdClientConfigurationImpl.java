package ee.cyber.cdoc2.config;

import java.util.Properties;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Mobile ID client properties loading.
 */
public class MobileIdClientConfigurationImpl implements Cdoc2Configuration {

    private final Properties properties;

    public MobileIdClientConfigurationImpl(Properties properties) {
        this.properties = properties;
    }

    @Override
    public MobileIdClientConfiguration mobileIdClientConfiguration()
        throws ConfigurationLoadingException {

        return MobileIdClientConfiguration.load(properties);
    }

}
