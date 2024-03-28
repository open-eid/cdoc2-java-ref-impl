package ee.cyber.cdoc2.server.conf;

import lombok.Value;

/**
 * Load test configuration
 *
 */
@Value
public class LoadTestConfig {

    LoadTestParameters createCapsule;
    LoadTestParameters getCapsule;
    /**
     * Delay before executing getCapsule scenario to allow for some capsules to be created
     * first so that there is input data for getCapsule tests available.
     */
    Long getCapsuleStartDelay;
}
