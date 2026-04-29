package ee.cyber.cdoc2.exceptions;

/**
 * Thrown in case of failed requests to RP Server client API.
 */
public class CdocRpClientException extends Exception {
    public CdocRpClientException(String message) {
        super(message);
    }

    /**
     * Constructor with message and additional cause
     * @param msg error message
     * @param cause original cause
     */
    public CdocRpClientException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
