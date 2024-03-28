package ee.cyber.cdoc2.cli;


import java.io.IOException;
import java.util.Properties;

import ee.cyber.cdoc2.util.Resources;

/**
 * Helper class for common usage.
 */
public final class CDocCommonHelper {

    private CDocCommonHelper() { }

    public static Properties getServerProperties(String keyServerPropertiesFile) throws IOException {
        Properties p = new Properties();
        p.load(Resources.getResourceAsStream(keyServerPropertiesFile));
        return p;
    }

}
