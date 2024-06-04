package ee.cyber.cdoc2.crypto;


/**
 * Identification for {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 */
public abstract class SemanticIdentification {

    private final String identifier;

    /**
     * Identifiers for Smart ID.
     * @param authType authentication method
     * @param etsiIdentifier ETSI identifier
     */
    protected SemanticIdentification(AuthenticationType authType, String etsiIdentifier) {
        this.identifier = authType + ":" + etsiIdentifier;
    }

    /**
     * Identifiers for Mobile ID.
     * @param authType authentication method
     * @param etsiIdentifier ETSI identifier
     * @param mobileNumber mobile number
     */
    protected SemanticIdentification(
        AuthenticationType authType,
        String etsiIdentifier,
        String mobileNumber
    ) {
        this.identifier = authType + ":" + etsiIdentifier + ":" + mobileNumber;
    }

    protected SemanticIdentification(String identifier) {
        this.identifier = identifier;
    }

    public String getIdentifier() {
        return this.identifier;
    }

    public String toString() {
        return "SemanticIdentification{identifier='" + this.identifier + "'}";
    }

    public enum AuthenticationType {
        SID,
        MID
    }

}
