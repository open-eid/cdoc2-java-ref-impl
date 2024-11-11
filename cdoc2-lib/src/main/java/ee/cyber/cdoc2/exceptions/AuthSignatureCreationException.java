package ee.cyber.cdoc2.exceptions;

/**
 * Signals that creation of auth signature has failed
 */
public class AuthSignatureCreationException extends Exception {
    public AuthSignatureCreationException(String message) {
        super(message);
    }

    public AuthSignatureCreationException(Throwable throwable) {
        super(throwable);
    }

    public AuthSignatureCreationException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
