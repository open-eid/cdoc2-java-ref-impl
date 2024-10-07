package ee.cyber.cdoc2.exceptions;


/**
 * Thrown when configuration properties are not found or not configured properly.
 */
public class ConfigurationLoadingException extends RuntimeException {

    /**
     * Constructor with message
     *
     * @param msg error message with the name of missing configuration file
     */
    public ConfigurationLoadingException(String msg) {
        super(msg);
    }

    /**
     * Constructor with message and additional cause
     *
     * @param msg   error message
     * @param cause original cause
     */
    public ConfigurationLoadingException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
