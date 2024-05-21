package ee.cyber.cdoc2.exceptions;


/**
 * Thrown in case of failed requests to Smart ID client API.
 */
public class SmartIdClientException extends Exception {

    public SmartIdClientException(String message) {
        super(message);
    }

    /**
     * Constructor with message and additional cause
     * @param msg   error message
     * @param cause original cause
     */
    public SmartIdClientException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
