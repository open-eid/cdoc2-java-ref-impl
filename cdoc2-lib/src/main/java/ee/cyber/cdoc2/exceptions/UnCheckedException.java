package ee.cyber.cdoc2.exceptions;

/**
 * Thrown when functional interface needs to convert checked exception into un-checked exception.
 */
public class UnCheckedException extends RuntimeException {
    public UnCheckedException(Throwable cause) {
        super(cause);
    }

    public UnCheckedException(String message) {
        super(message);
    }

    public UnCheckedException(String message, Throwable cause) {
        super(message, cause);
    }

}
