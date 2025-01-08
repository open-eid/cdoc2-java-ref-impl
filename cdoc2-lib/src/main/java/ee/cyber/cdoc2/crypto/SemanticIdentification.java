package ee.cyber.cdoc2.crypto;

import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import static ee.cyber.cdoc2.util.IdCodeValidationUtil.getValidatedIdentityCode;


/**
 * Identification for {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 */
public class SemanticIdentification {

    private static final String COLON_SEPARATOR = ":";
    public static final String ETSI_IDENTIFIER_PREFIX = "etsi/";
    private static final String ETSI_IDENTIFIER_SEPARATOR = "'";

    private final String identifier;

    /**
     * Identifiers for Smart ID or Mobile ID.
     * @param authType authentication method
     * @param etsiIdentifier for natural person identifier (ETSI identifier)
     */
    protected SemanticIdentification(AuthenticationType authType, SemanticsIdentifier etsiIdentifier) {
        this.identifier = authType + COLON_SEPARATOR + etsiIdentifier;
    }

    public String getIdentifier() {
        return this.identifier;
    }

    public String toString() {
        return "SemanticIdentification{identifier=" + ETSI_IDENTIFIER_SEPARATOR + this.identifier
            + ETSI_IDENTIFIER_SEPARATOR + "}";
    }

    public SemanticIdentification fromString(String semanticIdentification) {
        String authTypeString = semanticIdentification.substring(0, 3);
        AuthenticationType authType = AuthenticationType.of(authTypeString);
        SemanticsIdentifier semanticsIdentifier
            = new SemanticsIdentifier(extractEtsiIdentifier(semanticIdentification));

        if (authType == AuthenticationType.SID || authType == AuthenticationType.MID) {
            return new SemanticIdentification(authType, semanticsIdentifier);
        }
        throw new IllegalStateException(
            "Unexpected authentication type: " + authTypeString
        );
    }

    /**
     * Extract plain ETSI identifier from Semantic identification string.
     * E.g. 'etsi/PNOEE-48010010101'
     * @param semanticIdentification Semantic identification string
     * @return ETSI identifier in plain text
     */
    private static String extractEtsiIdentifier(String semanticIdentification) {
        String identifier = semanticIdentification.substring(
            semanticIdentification.indexOf(ETSI_IDENTIFIER_SEPARATOR) + 1,
            semanticIdentification.lastIndexOf(ETSI_IDENTIFIER_SEPARATOR)
        );
        return ETSI_IDENTIFIER_PREFIX + identifier;
    }

    public String getEtsiIdentifier() {
        return extractEtsiIdentifier(this.identifier);
    }

    public enum AuthenticationType {
        SID,
        MID;

        public static AuthenticationType of(String type) {
            if (type.equals(SID.name()) || type.equals(MID.name())) {
                return valueOf(type);
            }
            throw new IllegalStateException("Unexpected authentication type: " + type);
        }
    }

    /**
     * Convert person identification code into semantic identifier format for Smart ID encryption
     * */
    public static SemanticIdentification forKeyShares(
        String identificationCode, AuthenticationType authType
    ) {
        getValidatedIdentityCode(identificationCode);
        SemanticsIdentifier etsiIdentifier = new SemanticsIdentifier(
            SemanticsIdentifier.IdentityType.PNO,
            SemanticsIdentifier.CountryCode.EE,
            identificationCode
        );
        return new SemanticIdentification(authType, etsiIdentifier);
    }

}
