package ee.cyber.cdoc2.util;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;


/**
 * Utility class for converting Duration to date and time.
 */
public final class DurationUtil {

    private DurationUtil() { }

    public static OffsetDateTime getExpiryTime(Duration duration) {
        return OffsetDateTime.now()
            .toInstant()
            .atZone(ZoneOffset.UTC)
            .plus(duration)
            .toOffsetDateTime();
    }

}
