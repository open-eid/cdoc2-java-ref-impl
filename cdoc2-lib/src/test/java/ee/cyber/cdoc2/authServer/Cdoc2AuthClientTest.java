package ee.cyber.cdoc2.authServer;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import ee.cyber.cdoc2.client.ExtApiException;
import ee.cyber.cdoc2.client.authserver.Cdoc2AuthClient;
import ee.cyber.cdoc2.client.model.AuthIdentity;
import ee.cyber.cdoc2.exceptions.ConfigurationLoadingException;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.ClientConfigurationUtil.getCdoc2AuthClientConfiguration;
import static org.junit.jupiter.api.Assertions.*;


public class Cdoc2AuthClientTest {

    private static final int WIREMOCK_PORT = 7500;
    private static final int SHORT_READ_TIMEOUT_MS = 500;

    private static final String DEFAULT_IDENTIFIER = "etsi/";
    private static final String IDENTIFIER_OK = "PNOEE-40504040001";
    private static final String DEFAULT_MOBILE_NR = "1234567890";
    private static final String DEFAULT_VERIFICATION_CODE = "1234";

    private final Cdoc2AuthClient cdoc2AuthClient;
    private Cdoc2AuthClientMock cdoc2AuthClientMock;

    Cdoc2AuthClientTest() throws ConfigurationLoadingException {
        this.cdoc2AuthClient = new Cdoc2AuthClient(getCdoc2AuthClientConfiguration());
    }

    @RegisterExtension
    static WireMockExtension wiremock = WireMockExtension.newInstance()
        .options(wireMockConfig()
            .httpsPort(WIREMOCK_PORT)
            .keystorePath("wiremock_keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .keystoreType("PKCS12")
        )
        .build();

    @BeforeEach
    void setUp() {
        cdoc2AuthClientMock = new Cdoc2AuthClientMock(wiremock);
    }

    @Test
    void successfulStartAuth() throws ExtApiException, JsonProcessingException {
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
    void successfulGetAutStatus() throws ExtApiException, JsonProcessingException {
        var authProccessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubForAuthStatus(authProccessUuid);

        var authProcessStatusResponse = cdoc2AuthClient.getAuthProcessStatus(authProccessUuid);

        assertNotNull(authProcessStatusResponse);
        assertNotNull(authProcessStatusResponse.getStatus());
        assertEquals("COMPLETE", authProcessStatusResponse.getStatus());
    }

    @Test
    void successfulGetWellKnownJwks() throws ExtApiException, JsonProcessingException {
        cdoc2AuthClientMock.stubForGetWellKnownJwks();

        var wellKnownResponse = cdoc2AuthClient.getWellKnown();

        assertNotNull(wellKnownResponse);
        assertFalse(wellKnownResponse.getKeys().isEmpty());
    }

    @Test
    void networkFaultStartAuth() {
        cdoc2AuthClientMock.stubStartAuthWithNetworkFault();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorStartAuth() {
        cdoc2AuthClientMock.stubStartAuthWithServerError();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().startsWith("Failed to start authentication process"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("AUTH_SERVER_ERROR_CODE"),
            "actual cause message: " + ex.getMessage());
    }

    @Test
    void badRequestStartAuth() {
        cdoc2AuthClientMock.stubStartAuthWith400();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().startsWith("Failed to start authentication process"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundStartAuth() {
        cdoc2AuthClientMock.stubStartAuthWith404();

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().startsWith("Failed to start authentication process"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutStartAuth() throws ConfigurationLoadingException {
        cdoc2AuthClientMock.stubStartAuthWithDelay();

        Cdoc2AuthClient clientWithTimeout =
            new Cdoc2AuthClient(getCdoc2AuthClientConfiguration(), SHORT_READ_TIMEOUT_MS);

        AuthIdentity authIdentity = new AuthIdentity()
            .identifier(DEFAULT_IDENTIFIER + IDENTIFIER_OK)
            .mobileNr(DEFAULT_MOBILE_NR);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.startAuth(authIdentity)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void badRequestGetAuthStatus() {
        var authProcessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubAuthStatusWith400(authProcessUuid);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.getAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve auth process status"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundGetAuthStatus() {
        var authProcessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubAuthStatusWith404(authProcessUuid);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.getAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve auth process status"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorGetAuthStatus() {
        var authProcessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubAuthStatusWithServerError(authProcessUuid);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> cdoc2AuthClient.getAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve auth process status"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutGetAuthStatus() throws ConfigurationLoadingException {
        var authProcessUuid = UUID.randomUUID();
        cdoc2AuthClientMock.stubAuthStatusWithDelay(authProcessUuid);

        Cdoc2AuthClient clientWithTimeout =
            new Cdoc2AuthClient(getCdoc2AuthClientConfiguration(), SHORT_READ_TIMEOUT_MS);

        Exception ex = assertThrows(
            ExtApiException.class,
            () -> clientWithTimeout.getAuthProcessStatus(authProcessUuid)
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void badRequestGetWellKnown() {
        cdoc2AuthClientMock.stubWellKnownWith400();

        Exception ex = assertThrows(
            ExtApiException.class,
            cdoc2AuthClient::getWellKnown
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve well-known JWKS"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Bad request"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void notFoundGetWellKnown() {
        cdoc2AuthClientMock.stubWellKnownWith404();

        Exception ex = assertThrows(
            ExtApiException.class,
            cdoc2AuthClient::getWellKnown
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve well-known JWKS"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Not found"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void serverErrorGetWellKnown() {
        cdoc2AuthClientMock.stubWellKnownWithServerError();

        Exception ex = assertThrows(
            ExtApiException.class,
            cdoc2AuthClient::getWellKnown
        );

        assertTrue(ex.getMessage().startsWith("Failed to retrieve well-known JWKS"),
            "actual message: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Unexpected server response"),
            "actual message: " + ex.getMessage());
    }

    @Test
    void timeoutGetWellKnown() throws ConfigurationLoadingException {
        cdoc2AuthClientMock.stubWellKnownWithDelay();

        Cdoc2AuthClient clientWithTimeout =
            new Cdoc2AuthClient(getCdoc2AuthClientConfiguration(), SHORT_READ_TIMEOUT_MS);

        Exception ex = assertThrows(
            ExtApiException.class,
            clientWithTimeout::getWellKnown
        );

        assertTrue(ex.getMessage().contains("Failed to connect to authentication server"),
            "actual message: " + ex.getMessage());
    }
}
