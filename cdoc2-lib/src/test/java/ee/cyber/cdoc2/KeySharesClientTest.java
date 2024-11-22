package ee.cyber.cdoc2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import ee.cyber.cdoc2.client.Cdoc2KeySharesApiClient;
import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClient;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.KeySharesClientImpl;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.exceptions.CDocUserException;

import static ee.cyber.cdoc2.ClientConfigurationUtil.initKeySharesConfiguration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class KeySharesClientTest {

    private static final byte[] AUTH_TICKET = new byte[32];
    private static final String SHARE_ID = "shareId";

    @InjectMocks
    KeySharesClientImpl clientImpl;

    @Mock
    KeySharesClient client;

    @Mock
    Cdoc2KeySharesApiClient apiClient;

    @Test
    void shouldCreateKeyShare() throws ExtApiException {
        KeyShare keyShare = getKeyShare();

        when(client.getServerIdentifier()).thenReturn("mock");
        when(client.storeKeyShare(any())).thenReturn(SHARE_ID);

        String shareId = client.storeKeyShare(keyShare);

        assertNotNull(shareId);
        assertEquals(SHARE_ID, shareId);
        assertEquals("mock", client.getServerIdentifier());
    }

    @Test
    void shouldGetCreatedKeyShare() throws ExtApiException {
        KeyShare keyShare = getKeyShare();

        when(client.getKeyShare(any(), any())).thenReturn(Optional.of(keyShare));
        Optional<KeyShare> createdKeyShare = client.getKeyShare(SHARE_ID, AUTH_TICKET);

        assertTrue(createdKeyShare.isPresent());
        assertEquals(keyShare, createdKeyShare.get());
    }

    @Test
    void shouldCreateAndGetSameKeyShare() throws ExtApiException {
        KeyShare keyShare = getKeyShare();

        when(client.storeKeyShare(any())).thenReturn(SHARE_ID);
        String shareId = client.storeKeyShare(keyShare);

        when(client.getKeyShare(any(), any())).thenReturn(Optional.of(keyShare));
        Optional<KeyShare> createdKeyShare = client.getKeyShare(shareId, AUTH_TICKET);

        assertTrue(createdKeyShare.isPresent());
        assertEquals(keyShare, createdKeyShare.get());
    }

    @Test
    void shouldCreateKeyShareNonce() throws ApiException {
        byte[] nonce = "nonce".getBytes(StandardCharsets.UTF_8);

        NonceResponse nonceResponse = new NonceResponse();
        nonceResponse.setNonce(nonce);
        
        when(client.createKeyShareNonce(any())).thenReturn(nonceResponse);

        NonceResponse response = client.createKeyShareNonce(SHARE_ID);

        assertEquals(nonceResponse, response);
        assertEquals(nonce, response.getNonce());
    }

    @Test
    void shouldInvokeApiWhenCreateKeyShare() throws ApiException, ExtApiException {
        KeyShare keyShare = getKeyShare();
        clientImpl.storeKeyShare(keyShare);

        verify(apiClient, times(1)).createKeyShare(keyShare);
    }

    @Test
    void shouldInvokeApiWhenCreateKeyShareNonce() throws ApiException {
        clientImpl.createKeyShareNonce(SHARE_ID);

        verify(apiClient, times(1)).createNonce(SHARE_ID);
    }

    @Test
    void shouldInvokeApiWhenGetKeyShare() throws ApiException, ExtApiException {
        clientImpl.getKeyShare(SHARE_ID, AUTH_TICKET);

        verify(apiClient, times(1)).getKeyShare(SHARE_ID, AUTH_TICKET);
    }

    @Test
    void shouldFindRequiredKeyShareClient() throws GeneralSecurityException {
        KeyShareClientFactory factory
            = KeySharesClientHelper.createFactory(initKeySharesConfiguration());
        Collection<KeySharesClient> clients = factory.getClients();
        for (KeySharesClient ksClient : clients) {
            String serverUrl = ksClient.getServerIdentifier();
            KeySharesClient clientByUrl = factory.getClientForServerUrl(serverUrl);

            assertEquals(ksClient.getServerIdentifier(), clientByUrl.getServerIdentifier());
        }
    }

    @Test
    void shouldFailToGetKeyShareClientWithWrongServerIdentifier() throws GeneralSecurityException {
        KeyShareClientFactory factory
            = KeySharesClientHelper.createFactory(initKeySharesConfiguration());

        assertThrows(CDocUserException.class, () ->
            factory.getClientForServerUrl("wrong_server_identifier")
        );
    }

    private KeyShare getKeyShare() {
        KeyShare keyShare = new KeyShare();
        keyShare.setShare(new byte[32]);
        keyShare.setRecipient("etsi/PNOEE-38001085718");

        return keyShare;
    }

}
