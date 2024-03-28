package ee.cyber.cdoc2.client;

import ee.cyber.cdoc2.CDocUserException;

public interface KeyCapsuleClientFactory {
    /**
     * Get Key server client
     * @param serverId unique server identifier
     * @return key server client or null if serverId was unknown
     * @throws CDocUserException when the requested server is not found
     */
    KeyCapsuleClient getForId(String serverId) throws CDocUserException;

}
