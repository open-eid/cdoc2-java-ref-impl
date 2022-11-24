package ee.cyber.cdoc20.client;

public interface KeyCapsuleClientFactory {
    /**
     * Get Key server client
     * @param serverId unique server identifier
     * @return key server client or null if serverId was unknown
     */
    KeyCapsuleClient getForId(String serverId);

}
