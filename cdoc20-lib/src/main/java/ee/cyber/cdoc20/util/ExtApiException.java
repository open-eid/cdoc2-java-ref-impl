package ee.cyber.cdoc20.util;

import ee.cyber.cdoc20.CDocException;

/**
 * ExtApiException indicates that calling external API has failed. Similar to generated
 * ee.cyber.cdoc20.client.api.ApiException, that can change when underlying implementing framework (jersey2 or others)
 * is changed. The purpose of current class is keep the method signatures same even, when underlying implementation is
 * swapped.
 */
public class ExtApiException extends CDocException {
    public ExtApiException(String msg) {
        super(msg);
    }

    public ExtApiException(Throwable t) {
        super(t);
    }

    public ExtApiException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
