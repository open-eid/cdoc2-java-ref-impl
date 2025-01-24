package ee.cyber.cdoc2.crypto;

import ee.sk.smartid.rest.dao.SemanticsIdentifier;

import ee.cyber.cdoc2.container.CDocParseException;

import static ee.cyber.cdoc2.util.IdCodeValidationUtil.getValidatedIdentityCode;


/**
 * Identification for {@link ee.cyber.cdoc2.crypto.KeyShareRecipientType#SID_MID}
 */
public class AuthenticationIdentifier {

    public static final String COLON_SEPARATOR = ":";
    public static final String ETSI_IDENTIFIER_PREFIX = "etsi/";
    private static final String ETSI_IDENTIFIER_SEPARATOR = "'";
    private static final int ID_CODE_LENGTH = 11;
    private static final String ID_CODE_SEPARATOR = "-";
    private static final int SEMANTICS_IDENTIFIER_LENGTH = 17;

    private final String identifier;

    /**
     * Identifiers for Smart ID or Mobile ID.
     * @param authIdentifier authentication identifier string
     */
    public AuthenticationIdentifier(String authIdentifier) {
        this.identifier = authIdentifier;
    }

    /**
     * Identifiers for Smart ID or Mobile ID.
     * @param authType authentication method
     * @param etsiIdentifier for natural person identifier (ETSI identifier)
     */
    protected AuthenticationIdentifier(AuthenticationType authType, SemanticsIdentifier etsiIdentifier) {
        this.identifier = authType + COLON_SEPARATOR + etsiIdentifier.getIdentifier();
    }

    /**
     * Identifiers for Mobile ID.
     * @param authType authentication method
     * @param etsiIdentifier for natural person identifier (ETSI identifier)
     * @param mobileNumber mobile number
     */
    protected AuthenticationIdentifier(
        AuthenticationType authType,
        SemanticsIdentifier etsiIdentifier,
        String mobileNumber
    ) {
        this.identifier = authType + ":" + etsiIdentifier.getIdentifier() + ":" + mobileNumber;
    }

    public String getIdentifier() {
        return this.identifier;
    }

    public String toString() {
        return "AuthenticationIdentifier{identifier=" + ETSI_IDENTIFIER_SEPARATOR + this.identifier
            + ETSI_IDENTIFIER_SEPARATOR + "}";
    }

    public AuthenticationType getAuthType() {
        return extractAuthType(this.identifier);
    }

    public String getMobileNumber() {
        return extractMobileNumber(this.identifier);
    }

    public String getIdCode() {
        return extractIdCode(this.identifier);
    }

    public static String getAuthIdentifierWithoutPhoneNr(String authIdentifier)
        throws CDocParseException {
        return removeMobileNumber(authIdentifier);
    }

    private static AuthenticationType extractAuthType(String authIdentifier) {
        String authTypeString = authIdentifier.substring(0, 3);
        return AuthenticationType.of(authTypeString);
    }

    private static String extractMobileNumber(String authIdentifier) {
        if (AuthenticationIdentifier.AuthenticationType.MID == extractAuthType(authIdentifier)) {
            int begin = authIdentifier.lastIndexOf(COLON_SEPARATOR) + 1;
            return authIdentifier.substring(begin);
        }

        return null;
    }

    private String extractIdCode(String authIdentifier) {
        int begin = authIdentifier.indexOf(ID_CODE_SEPARATOR) + 1;
        return authIdentifier.substring(begin, begin + ID_CODE_LENGTH);
    }

    private static String removeMobileNumber(String authIdentifier)
        throws CDocParseException {
        try {
            int end = authIdentifier.lastIndexOf(COLON_SEPARATOR);
            return authIdentifier.substring(0, end);
        } catch (IndexOutOfBoundsException e) {
            throw new CDocParseException("Required phone number is missing");
        }
    }

    /**
     * Extract plain ETSI identifier from authentication identifier string.
     * E.g. 'etsi/PNOEE-48010010101'
     * @param authIdentifier authentication identifier string
     * @return ETSI identifier in plain text
     */
    private static String extractEtsiIdentifier(String authIdentifier) {
        int begin = authIdentifier.indexOf(COLON_SEPARATOR) + 1;
        int end = begin + SEMANTICS_IDENTIFIER_LENGTH;
        String identifier = authIdentifier.substring(begin, end);
        return ETSI_IDENTIFIER_PREFIX + identifier;
    }

    public String getEtsiIdentifier() {
        return extractEtsiIdentifier(this.identifier);
    }

    /**
     * ETSI Natural Person Semantics Identifier as example "PNOEE-48010010101". Wrapped into
     * SemanticsIdentifier object
     * */
    public SemanticsIdentifier getSemanticsIdentifier()  {
        int begin = this.identifier.indexOf(COLON_SEPARATOR) + 1;
        int end = begin + SEMANTICS_IDENTIFIER_LENGTH;
        // PNOEE-48010010101
        String plainIdentifier = this.identifier.substring(begin, end);
        return new SemanticsIdentifier(plainIdentifier);
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
     * Create authentication identifier format for Smart ID or Mobile ID encryption
     */
    public static AuthenticationIdentifier forKeyShares(
        SemanticsIdentifier etsiIdentifier, AuthenticationType authType
    ) {
        return new AuthenticationIdentifier(authType, etsiIdentifier);
    }

    /**
     * Create authentication identifier format for Mobile ID decryption
     */
    public static AuthenticationIdentifier forMidDecryption(
        SemanticsIdentifier semanticsIdentifier,
        String phoneNumber
    ) {
        return new AuthenticationIdentifier(
            AuthenticationType.MID, semanticsIdentifier, phoneNumber
        );
    }

    /**
     * Create semantics identifier
     */
    public static SemanticsIdentifier createSemanticsIdentifier(String idCode) {
        return new SemanticsIdentifier(
            SemanticsIdentifier.IdentityType.PNO,
            SemanticsIdentifier.CountryCode.EE,
            getValidatedIdentityCode(idCode)
        );
    }

    /**
     * Smart-ID and Mobile-ID interaction parameters.
     * @param document document to be decrypted, will be displayed to user when user PIN is required
     */
    public record SidMidInteractionParams(
        String document
    ) {
    }
}
