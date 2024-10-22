package ee.cyber.cdoc2.client;

import java.util.Optional;

import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;


/**
 * Client for Key Shares servers (there are few of servers).
 */
public interface KeySharesClient extends ServerClient {

    /**
     * Creates key share for {@link KeySharesCapsule for fbs.recipients.KeySharesCapsule}.
     * @param keyShare key share
     * @return created key share ID
     */
    String storeKeyShare(KeyShare keyShare) throws ExtApiException;

    /**
     * Create server nonce for authentication signature.
     * @param shareId key share ID
     * @return NonceResponse created server nonce response
     */
    NonceResponse createKeyShareNonce(String shareId) throws ApiException;

    /**
     * Get key share by share ID.
     * @param shareId key share ID
     * @param authTicket server authentication ticket
     * @return KeyShare key share
     */
    Optional<KeyShare> getKeyShare(String shareId, byte[] authTicket) throws ExtApiException;

}
