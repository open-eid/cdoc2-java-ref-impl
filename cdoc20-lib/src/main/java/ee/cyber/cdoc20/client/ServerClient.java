package ee.cyber.cdoc20.client;

public interface ServerClient {

    /**
     * Get unique server identifier
     * @return serverId that identifies server that this ServerClient is connected to
     */
    String getServerIdentifier();
}
