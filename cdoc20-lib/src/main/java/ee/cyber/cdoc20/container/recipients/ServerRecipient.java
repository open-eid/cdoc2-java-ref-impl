package ee.cyber.cdoc20.container.recipients;

/**
 * Recipient type that gets ephemeral key material from server
 */
public interface ServerRecipient {
    String getKeyServerId();
    String getTransactionId();
}
