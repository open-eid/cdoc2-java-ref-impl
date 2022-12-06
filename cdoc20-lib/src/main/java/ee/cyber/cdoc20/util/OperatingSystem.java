package ee.cyber.cdoc20.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Operating system.
 */
public enum OperatingSystem {
    WINDOWS,
    LINUX,
    MAC;

    private static final Logger log = LoggerFactory.getLogger(OperatingSystem.class);

    /**
     * @return the operating system
     */
    public static OperatingSystem getOS() {
        log.debug("os.family: {}, os.name: {}", System.getProperty("os.family"), System.getProperty("os.name"));
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            return OperatingSystem.WINDOWS;
        }
        if (os.contains("nix") || os.contains("nux")) {
            return OperatingSystem.LINUX;
        }
        if (os.contains("mac")) {
            return OperatingSystem.MAC;
        }

        log.error("Unknown operating system: os.family: {}, os.name: {}",
            System.getProperty("os.family"), System.getProperty("os.name")
        );
        throw new IllegalStateException("Unknown OS");
    }
}
