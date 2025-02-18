package ee.cyber.cdoc2.container;

import ee.cyber.cdoc2.exceptions.CDocException;


public class CDocParseException extends CDocException {

    public CDocParseException(String msg) {
        super(msg);
    }

    public CDocParseException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
