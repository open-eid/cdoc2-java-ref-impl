package ee.cyber.cdoc2.client.authServer;

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
