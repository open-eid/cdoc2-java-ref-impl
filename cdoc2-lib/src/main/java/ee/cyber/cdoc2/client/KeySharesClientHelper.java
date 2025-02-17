package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.UserErrorCode;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.exceptions.CDocUserException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;


/**
 * KeyShareClientFactory implementation class for creating and requesting key shares clients
 */
public class KeySharesClientHelper implements KeySharesClientFactory {

    private static final Logger log = LoggerFactory.getLogger(KeySharesClientHelper.class);

    private final Collection<KeySharesClient> clients;
    private final KeySharesConfiguration configuration;

    public KeySharesClientHelper(
        Collection<KeySharesClient> keyShareClients,
        KeySharesConfiguration sharesConfiguration
    ) {
        this.clients = keyShareClients;
        this.configuration = sharesConfiguration;
    }

    /**
     * Initialize Key share client instance for specified server.
     * @param configuration Key Shares configuration
     * @return Key share client factory
     * @throws CDocUserException when the requested server is not found
     */
    public static KeySharesClientFactory createFactory(KeySharesConfiguration configuration)
        throws GeneralSecurityException {
        return initKeySharesClientByServer(configuration);
    }

    @Override
    public Collection<KeySharesClient> getClients() {
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
        return configuration;
    }

    private static KeySharesClientHelper initKeySharesClientByServer(
        KeySharesConfiguration configuration
    ) throws GeneralSecurityException {

        Set<String> servers = configuration.getKeySharesServersUrls();
        Collection<KeySharesClient> keyShareClients = new LinkedList<>();
        for (String server : servers) {
            keyShareClients.add(KeySharesClientImpl.create(server, configuration));
        }

        return new KeySharesClientHelper(keyShareClients, configuration);
    }

}
