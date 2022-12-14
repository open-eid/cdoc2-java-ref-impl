package ee.cyber.cdoc20.container;

import ee.cyber.cdoc20.CDocException;

public class CDocParseException extends CDocException {

    public CDocParseException(String msg) {
        super(msg);
    }

    public CDocParseException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
