package ee.cyber.cdoc2.container;

/**
 * Thrown to indicate that FlatBuffer contains a record type that the current version of cdoc-lib cannot handle
 */
public class UnknownFlatBufferTypeException extends CDocParseException {
    public UnknownFlatBufferTypeException(String msg) {
        super(msg);
    }
}
