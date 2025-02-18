package ee.cyber.cdoc2.config;

import ee.cyber.cdoc2.ClientConfigurationUtil;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static org.junit.jupiter.api.Assertions.assertEquals;


class MobileIdConfigurationTest {

    private static final String HOST_URL = "https://tsp.demo.sk.ee/mid-api";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";

    @Test
    void loadMobileIdConfigurationProperties() throws ConfigurationLoadingException {

        MobileIdClientConfiguration mobileIdClientConfiguration =
            ClientConfigurationUtil.getMobileIdDemoEnvConfiguration();

        assertEquals(HOST_URL, mobileIdClientConfiguration.getHostUrl());
        assertEquals(RELYING_PARTY_UUID, mobileIdClientConfiguration.getRelyingPartyUuid());
        assertEquals(RELYING_PARTY_NAME, mobileIdClientConfiguration.getRelyingPartyName());
    }

}
