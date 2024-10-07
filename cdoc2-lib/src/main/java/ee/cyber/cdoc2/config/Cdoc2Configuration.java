package ee.cyber.cdoc2.config;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.smartid.SmartIdClientConfiguration;


/**
 * Common configuration interface for loading properties.
 */
public interface Cdoc2Configuration {

    default SmartIdClientConfiguration smartIdClientConfiguration() throws ConfigurationLoadingException {
        return null;
    }

    default KeySharesConfiguration keySharesConfiguration()
        throws ConfigurationLoadingException {
        return null;
    }

}
