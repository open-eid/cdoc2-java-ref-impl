package ee.cyber.cdoc2.config;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;
import ee.cyber.cdoc2.smartid.SmartIdClientConfiguration;

import static ee.cyber.cdoc2.ClientConfigurationUtil.getSmartIdConfiguration;
import static org.junit.jupiter.api.Assertions.assertEquals;


class SmartIdConfigurationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";

    @Test
    void loadSmartIdConfigurationProperties() throws ConfigurationLoadingException {
        SmartIdClientConfiguration smartIdClientConfiguration
            = getSmartIdConfiguration();

        assertEquals(HOST_URL, smartIdClientConfiguration.getHostUrl());
        assertEquals(RELYING_PARTY_UUID, smartIdClientConfiguration.getRelyingPartyUuid());
        assertEquals(RELYING_PARTY_NAME, smartIdClientConfiguration.getRelyingPartyName());
    }

}
