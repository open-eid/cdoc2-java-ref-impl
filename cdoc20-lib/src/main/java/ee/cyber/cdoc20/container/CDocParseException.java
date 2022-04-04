package ee.cyber.cdoc20.container;

public class CDocParseException extends Exception {

    public CDocParseException(String msg) {
        super(msg);
    }

    public CDocParseException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
