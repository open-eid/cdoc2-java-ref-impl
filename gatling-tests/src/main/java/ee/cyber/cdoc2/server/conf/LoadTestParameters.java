package ee.cyber.cdoc2.server.conf;

import lombok.Value;

@Value
public class LoadTestParameters {
    Long incrementUsersPerSec;
    int incrementCycles;
    Long cycleDurationSec;
    Long startingUsersPerSec;
}
