package ee.cyber.cdoc2.client;

import java.security.GeneralSecurityException;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.config.KeySharesConfiguration;

import static ee.cyber.cdoc2.util.ApiClientUtil.handleOpenApiException;
import static ee.cyber.cdoc2.util.ApiClientUtil.loadClientTrustKeyStore;


/**
 * KeySharesClient implementation to connect {@link Cdoc2KeySharesApiClient}.
 */
public final class KeySharesClientImpl implements KeySharesClient {

    private static final Logger log = LoggerFactory.getLogger(KeySharesClientImpl.class);

    private final Cdoc2KeySharesApiClient apiClient;
    private final String serverUrl;

    private KeySharesClientImpl(
        Cdoc2KeySharesApiClient keySharesApiClient,
        String serverUrl
    ) {
        this.apiClient = keySharesApiClient;
        this.serverUrl = serverUrl;
    }

    @Override
    public String getServerIdentifier() {
        return this.serverUrl;
    }

    static KeySharesClient create(String serverUrl, KeySharesConfiguration config)
        throws GeneralSecurityException {

        var builder = Cdoc2KeySharesApiClient.builder();
        builder.withBaseUrl(serverUrl);

        builder.withTrustKeyStore(loadClientTrustKeyStore(
            config.getClientTrustStore(),
            config.getClientTrustStoreType(),
            config.getClientTrustStorePw()
        ));
        Cdoc2KeySharesApiClient keySharesApiClient = builder.build();
        return new KeySharesClientImpl(keySharesApiClient, serverUrl);
    }

    @Override
    public String storeKeyShare(KeyShare keyShare) throws ExtApiException {
        try {
            return apiClient.createKeyShare(keyShare);
        } catch (ApiException e) {
            throw new ExtApiException("Failed to save key share", e);
        }
    }

    @Override
    public NonceResponse createKeyShareNonce(String shareId) throws ApiException {
        return apiClient.createNonce(shareId);
    }

    @Override
    public Optional<KeyShare> getKeyShare(String shareId, byte[] authTicket) throws ExtApiException {
        Optional<KeyShare> result = Optional.empty();
        try {
            result = apiClient.getKeyShare(shareId, authTicket);
        } catch (Exception e) {
            log.error("Failed to get key share", e);
            handleOpenApiException(e);
        }
        return result;
    }

}
