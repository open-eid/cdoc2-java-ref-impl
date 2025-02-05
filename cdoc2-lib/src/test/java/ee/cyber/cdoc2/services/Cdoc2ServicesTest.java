package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static ee.cyber.cdoc2.ClientConfigurationUtil.DEMO_ENV_PROPERTIES;
import static org.junit.jupiter.api.Assertions.*;

class Cdoc2ServicesTest {

    @Test
    void testInitFromProperties() throws GeneralSecurityException {
        Services services = Cdoc2Services.initFromProperties(DEMO_ENV_PROPERTIES);
        assertTrue(services.hasService(SmartIdClient.class));
    }
}
