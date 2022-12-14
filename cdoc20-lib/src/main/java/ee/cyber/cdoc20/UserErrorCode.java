package ee.cyber.cdoc20;

/**
 * Error codes for displaying to the end-user.
 *
 */
public enum UserErrorCode {

    /**
     * The key server specified in the CDOC 2.0 document was not found in the configured server list.
     */
    SERVER_NOT_FOUND,

    /**
     * A network error occurred.
     */
    NETWORK_ERROR,

    /**
     * Wrong pin entered.
     */
    WRONG_PIN,

    /**
     * The pin is locked.
     */
    PIN_LOCKED,

    /**
     * The smart card is not present.
     */
    SMART_CARD_NOT_PRESENT,

    /**
     * The user cancelled the operation.
     */
    USER_CANCEL;
}
