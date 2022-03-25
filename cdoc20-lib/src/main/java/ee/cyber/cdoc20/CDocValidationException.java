package ee.cyber.cdoc20;

public class CDocValidationException extends Exception{

    public CDocValidationException(String msg) {
        super(msg);
    }

    public CDocValidationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
