package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.config.CDoc2ConfigurationProvider;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * KeyShareClientFactory implementation class for creating and requesting key shares clients
 */
public class KeySharesClientHelper implements KeyShareClientFactory {

    private static final Logger log = LoggerFactory.getLogger(KeySharesClientHelper.class);

    private final Collection<KeySharesClient> clients;

    public KeySharesClientHelper(Collection<KeySharesClient> keyShareClients) {
        this.clients = keyShareClients;
    }

    /**
     * Initialize Key share client instance for specified server.
     * @return Key share client factory
     * @throws CDocUserException when the requested server is not found
     */
    public static KeyShareClientFactory createFactory() throws GeneralSecurityException {
        return initKeySharesClientByServer();
    }

    /**
     * Initialize Key share client instance for specified server.
     * @param configuration Key Shares configuration
     * @return Key share client factory
     * @throws CDocUserException when the requested server is not found
     */
    public static KeyShareClientFactory createFactory(KeySharesConfiguration configuration)
        throws GeneralSecurityException {
        return initKeySharesClientByServer(configuration);
    }

    @Override
    public Collection<KeySharesClient> getClients() {
        // ToDo remove the collection of clients when multi servers are implemented
        return clients;
    }

    @Override
    public KeySharesClient getClientForServerUrl(String serverUrl) throws CDocUserException {

        return clients.stream()
            .filter(client -> client.getServerIdentifier().equals(serverUrl))
            .findAny()
            .orElseThrow(() -> {
                log.error("Server configuration for {} not provided", serverUrl);
                return new CDocUserException(
                    UserErrorCode.SERVER_NOT_FOUND,
                    String.format("Server configuration for server URL '%s' not found", serverUrl)
                );
            });
    }

    @Override
    public KeySharesConfiguration getKeySharesConfiguration() throws ConfigurationLoadingException {
        return CDoc2ConfigurationProvider.getConfiguration().keySharesConfiguration();
    }

    private static KeySharesClientHelper initKeySharesClientByServer() throws GeneralSecurityException {
        KeySharesConfiguration keySharesConfiguration
            = CDoc2ConfigurationProvider.getConfiguration().keySharesConfiguration();

        return initKeySharesClientByServer(keySharesConfiguration);
    }

    private static KeySharesClientHelper initKeySharesClientByServer(
        KeySharesConfiguration configuration
    ) throws GeneralSecurityException {

        Set<String> servers = configuration.getKeySharesServersUrls();
        // ToDo create multithreading for servers here i.o. for loop. Create client instances with
        //  own server URL
        Collection<KeySharesClient> keyShareClients = new LinkedList<>();
        for (String server : servers) {
            keyShareClients.add(KeySharesClientImpl.create(server, configuration));
        }

        return new KeySharesClientHelper(keyShareClients);
    }

}
