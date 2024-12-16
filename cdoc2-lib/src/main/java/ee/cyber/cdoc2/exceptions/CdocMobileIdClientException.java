package ee.cyber.cdoc2.exceptions;


/**
 * Thrown in case of failed requests to Mobile ID client API.
 */
public class CdocMobileIdClientException extends Exception {

    public CdocMobileIdClientException(String message) {
        super(message);
    }

    /**
     * Constructor with message and additional cause
     * @param msg error message
     * @param cause original cause
     */
    public CdocMobileIdClientException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
