package ee.cyber.cdoc2.config;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration;
import static org.junit.jupiter.api.Assertions.assertEquals;


class Cdoc2RpClientConfigurationTest {
    private static final String HOST_URL = "http://localhost:9080";
    private static final String CERTIFICATE_LEVEL = "QUALIFIED";

    @Test
    void loadSmartIdConfigurationProperties() throws ConfigurationLoadingException {
        Cdoc2RpClientConfiguration rpClientConfiguration = getCdoc2RpClientDemoEnvConfiguration();

        assertEquals(HOST_URL, rpClientConfiguration.getHostUrl());
        assertEquals(CERTIFICATE_LEVEL, rpClientConfiguration.getCertificateLevel());
    }
}
