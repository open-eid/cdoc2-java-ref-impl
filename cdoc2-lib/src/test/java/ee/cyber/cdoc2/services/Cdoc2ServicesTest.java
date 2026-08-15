package ee.cyber.cdoc2.services;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.client.RpClient;

import static ee.cyber.cdoc2.ClientConfigurationUtil.DEMO_ENV_PROPERTIES;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Cdoc2ServicesTest {

    @Test
    void testInitFromProperties() throws GeneralSecurityException {
        Services services = Cdoc2Services.initFromProperties(DEMO_ENV_PROPERTIES);
        assertTrue(services.hasService(RpClient.class));
    }
}
