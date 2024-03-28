package ee.cyber.cdoc2;

/**
 * CDOC2exception with error code.
 */
public class CDocUserException extends RuntimeException {
    private final UserErrorCode errorCode;

    /**
     * Constructor
     *
     * @param code the error code
     * @param message the error message
     */
    public CDocUserException(UserErrorCode code, String message) {
        super(message);
        this.errorCode = code;
    }

    /**
     * @return the error code
     */
    public UserErrorCode getErrorCode() {
        return this.errorCode;
    }

    @Override
    public String toString() {
        return String.format("errorCode: %s, errorMessage: %s", this.errorCode, this.getMessage());
    }
}
