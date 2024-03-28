package ee.cyber.cdoc2.server;

import org.springframework.boot.context.metrics.buffering.BufferingApplicationStartup;

/**
 * Utilities for server monitoring.
 */
public final class MonitoringUtil {

    private MonitoringUtil() {
    }

    /**
     * @return application startup information
     */
    public static BufferingApplicationStartup getApplicationStartupInfo() {
        var startup = new BufferingApplicationStartup(2048);
        // the default application startup has too much details, filter only required info
        startup.addFilter(startupStep -> startupStep.getName().matches("timeline.startTime"));
        return startup;
    }
}
