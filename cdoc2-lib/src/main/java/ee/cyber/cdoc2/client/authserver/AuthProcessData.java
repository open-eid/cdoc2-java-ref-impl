package ee.cyber.cdoc2.client.authserver;

import java.util.UUID;


/**
 * CDOC2 Authentication process data
 * @param uuid
 * @param verificationCode
 */
public record AuthProcessData(
    UUID uuid,
    String verificationCode
) {
}
