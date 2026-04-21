package ee.cyber.cdoc2.exceptions;

/**
 * Thrown in case of failed requests to Auth Server client API.
 */
public class CdocAuthClientException extends Exception {
    public CdocAuthClientException(String message) {
        super(message);
    }

    /**
     * Constructor with message and additional cause
     * @param msg error message
     * @param cause original cause
     */
    public CdocAuthClientException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
