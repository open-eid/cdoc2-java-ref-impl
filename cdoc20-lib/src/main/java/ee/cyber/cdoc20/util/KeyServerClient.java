package ee.cyber.cdoc20.util;

import java.security.interfaces.ECPublicKey;
import java.util.Optional;

public interface KeyServerClient {
    /**
     * Store senderKey in server
     * @param receiverKey recipient key
     * @param senderKey sender key
     * @return transactionId to retrieve senderKey from the server
     * @throws ExtApiException if error happens
     */
    String storeSenderKey(ECPublicKey receiverKey, ECPublicKey senderKey) throws ExtApiException;

    /**
     * Retrieve previously stored sender key using transaction id
     * @param transactionId transaction id returned by #storeSenderKey method
     * @return Sender key stored under transactionId or empty Optional if key was not found for transactionId
     * @throws ExtApiException if error happens
     */
    Optional<ECPublicKey> getSenderKey(String transactionId) throws ExtApiException;

    /**
     * Get unique server identifier
     * @return serverId that identifies server that this KeyServerClient is connected to
     */
    String getServerIdentifier();
}
