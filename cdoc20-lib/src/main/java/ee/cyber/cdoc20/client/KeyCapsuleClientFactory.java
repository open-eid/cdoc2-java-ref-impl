package ee.cyber.cdoc20.client;

import ee.cyber.cdoc20.CDocUserException;

public interface KeyCapsuleClientFactory {
    /**
     * Get Key server client
     * @param serverId unique server identifier
     * @return key server client or null if serverId was unknown
     * @throws CDocUserException when the requested server is not found
     */
    KeyCapsuleClient getForId(String serverId) throws CDocUserException;

}
