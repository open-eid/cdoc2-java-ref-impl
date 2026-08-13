package ee.cyber.cdoc2.config;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static ee.cyber.cdoc2.ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration;
import static org.junit.jupiter.api.Assertions.assertEquals;


class RpClientConfigurationTest {
    private static final String HOST_URL = "https://localhost:7600";

    @Test
    void loadSmartIdConfigurationProperties() throws ConfigurationLoadingException {
        RpClientConfiguration rpClientConfiguration = getCdoc2RpClientDemoEnvConfiguration();

        assertEquals(HOST_URL, rpClientConfiguration.getHostUrl());
        assertEquals(
            RpClientConfigurationProps.CertificateLevel.QUALIFIED,
            rpClientConfiguration.getCertificateLevel()
        );
    }
}
