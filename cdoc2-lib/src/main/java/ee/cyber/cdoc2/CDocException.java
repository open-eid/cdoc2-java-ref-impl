package ee.cyber.cdoc2;


public class CDocException extends Exception {
    public CDocException(String msg) {
        super(msg);
    }

    public CDocException(Throwable t) {
        super(t);
    }

    public CDocException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
