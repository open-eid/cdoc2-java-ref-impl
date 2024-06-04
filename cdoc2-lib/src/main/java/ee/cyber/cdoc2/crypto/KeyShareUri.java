package ee.cyber.cdoc2.crypto;

import ee.cyber.cdoc2.fbs.recipients.KeySharesCapsule;


/**
 * Key share URI data {@link KeyShareUri fbs.recipients.KeyShare} inside
 * {@link KeySharesCapsule fbs.recipients.KeySharesCapsule}.
 */
public record KeyShareUri(
    String serverBaseUrl,
    String shareId
) {
}
