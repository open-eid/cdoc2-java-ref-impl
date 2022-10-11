package ee.cyber.cdoc20.util;

public interface KeyServerClientFactory {
    /**
     * Get Key server client
     * @param serverId unique server identifier
     * @return key server client or null if serverId was unknown
     */
    KeyServerClient getForId(String serverId);
}
