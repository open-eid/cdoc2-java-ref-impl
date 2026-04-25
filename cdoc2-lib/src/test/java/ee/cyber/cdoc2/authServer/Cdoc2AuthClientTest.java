package ee.cyber.cdoc2.authServer;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import ee.cyber.cdoc2.client.authserver.Cdoc2AuthClient;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.exceptions.CdocAuthClientException;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.ClientConfigurationUtil.getCdoc2AuthClientConfiguration;
import static org.junit.jupiter.api.Assertions.*;


public class Cdoc2AuthClientTest {

    private static final int WIREMOCK_PORT = 8080;

    private static final String DEFAULT_IDENTIFIER = "etsi/";
    private static final String IDENTIFIER_OK = "PNOEE-40504040001-DEM0-Q";
    private static final String DEFAULT_MOBILE_NR = "1234567890";
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    private final Cdoc2AuthClient cdoc2AuthClient;
    private Cdoc2AuthClientMock cdoc2AuthClientMock;


    Cdoc2AuthClientTest() throws ConfigurationLoadingException {
        this.cdoc2AuthClient = new Cdoc2AuthClient(getCdoc2AuthClientConfiguration());
    }

    @RegisterExtension
    static WireMockExtension wiremock = WireMockExtension.newInstance()
        .options(wireMockConfig().port(WIREMOCK_PORT))
        .build();

    @BeforeEach
    void setUp() {
        cdoc2AuthClientMock = new Cdoc2AuthClientMock(wiremock);
    }

    @Test
    void successfulStartAuth() throws CdocAuthClientException, JsonProcessingException {
        var authProccessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubStartAuthResp(authProccessUuid);

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        var startAuthResponse = cdoc2AuthClient.startAuth(authIdentity);
        assertEquals(authProccessUuid, startAuthResponse.uuid());
        assertEquals(DEFAULT_VERIFICATION_CODE, startAuthResponse.verificationCode());
    }

    @Test
    void successfulGetAutStatus() throws CdocAuthClientException, JsonProcessingException {
        var authProccessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubForAuthStatus(authProccessUuid);

        var authProcessStatusResponse = cdoc2AuthClient.getAuthProcessStatus(authProccessUuid);

        assertNotNull(authProcessStatusResponse);
        assertNotNull(authProcessStatusResponse.getStatus());
        assertEquals("COMPLETE", authProcessStatusResponse.getStatus());
    }

    @Test
    void successfulGetWellKnownJwks() throws CdocAuthClientException, JsonProcessingException {
        cdoc2AuthClientMock.stubForGetWellKnownJwks();

        var wellKnownResponse = cdoc2AuthClient.getWellKnown();

        assertNotNull(wellKnownResponse);
        assertFalse(wellKnownResponse.getKeys().isEmpty());
    }
}
