package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.smartid.SmartIdClientTest;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Properties;

import static ee.cyber.cdoc2.config.Cdoc2ConfigurationProperties.SMART_ID_PROPERTIES;
import static org.junit.jupiter.api.Assertions.*;

class Cdoc2ServicesTest {

    @Test
    void testInitFromProperties() throws GeneralSecurityException {
        Properties propLocations = new Properties();
        propLocations.setProperty(SMART_ID_PROPERTIES, SmartIdClientTest.demoEnvProperties);
        Services services = Cdoc2Services.initFromProperties(propLocations);
        assertTrue(services.hasService(SmartIdClient.class));
    }
}
