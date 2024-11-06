package ee.cyber.cdoc2.client;

import java.util.Collection;

import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * Factory for requesting key shares clients {@link KeySharesClient}
 */
public interface KeyShareClientFactory {

    /**
     * Get all defined Key share clients
     * @return the collection of key share server clients
     * @throws CDocUserException when the requested server is not found
     */
    Collection<KeySharesClient> getClients() throws CDocUserException;

    /**
     * Get Key share client by server URL
     * @param serverUrl server identifier
     * @return key share server client or null if server URL was unknown
     * @throws CDocUserException when the requested server is not found
     */
    KeySharesClient getClientForServerUrl(String serverUrl) throws CDocUserException;

    /**
     * Get Key shares configuration.
     * @return Key shares configuration
     * @throws ConfigurationLoadingException if configuration loading is failed
     */
    KeySharesConfiguration getKeySharesConfiguration() throws ConfigurationLoadingException;

}
