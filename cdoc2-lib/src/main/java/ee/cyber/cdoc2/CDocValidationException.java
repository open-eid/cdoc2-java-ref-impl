package ee.cyber.cdoc2;

public class CDocValidationException extends Exception {

    public CDocValidationException(String msg) {
        super(msg);
    }

    public CDocValidationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
